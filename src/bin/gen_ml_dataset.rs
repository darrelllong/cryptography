use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use cryptography::{
    Aes128, Aes256, BlockCipher, Des, Grasshopper, Magma, Simon128_128, Sm4, Speck128_128,
    TripleDes, Zuc128,
};

const DEFAULT_SAMPLE_LEN: usize = 32;

type SampleFn = fn(&mut SplitMix64, &mut [u8]);

struct CipherSpec {
    name: &'static str,
    generate: SampleFn,
}

const CIPHERS: &[CipherSpec] = &[
    CipherSpec {
        name: "aes128",
        generate: gen_aes128,
    },
    CipherSpec {
        name: "aes256",
        generate: gen_aes256,
    },
    CipherSpec {
        name: "des",
        generate: gen_des,
    },
    CipherSpec {
        name: "tdes3",
        generate: gen_tdes3,
    },
    CipherSpec {
        name: "simon128_128",
        generate: gen_simon128_128,
    },
    CipherSpec {
        name: "speck128_128",
        generate: gen_speck128_128,
    },
    CipherSpec {
        name: "magma",
        generate: gen_magma,
    },
    CipherSpec {
        name: "grasshopper",
        generate: gen_grasshopper,
    },
    CipherSpec {
        name: "sm4",
        generate: gen_sm4,
    },
    CipherSpec {
        name: "zuc128",
        generate: gen_zuc128,
    },
    CipherSpec {
        name: "random",
        generate: gen_random,
    },
];

#[derive(Clone, Debug)]
struct Config {
    output: PathBuf,
    sample_len: usize,
    train_per_class: usize,
    val_per_class: usize,
    test_per_class: usize,
    seed: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output: PathBuf::from("ml/data"),
            sample_len: DEFAULT_SAMPLE_LEN,
            train_per_class: 20_000,
            val_per_class: 4_000,
            test_per_class: 4_000,
            seed: None,
        }
    }
}

#[derive(Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn from_os() -> io::Result<Self> {
        let mut file = File::open("/dev/urandom")?;
        let mut seed = [0u8; 8];
        file.read_exact(&mut seed)?;
        Ok(Self::from_seed(u64::from_le_bytes(seed)))
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        // This simple modulo has slight bias when `upper` is not a power of
        // two. That is acceptable here because it is only used for shuffling
        // dataset rows, not for any cryptographic purpose.
        (self.next_u64() % upper as u64) as usize
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0usize;
        while i < buf.len() {
            let bytes = self.next_u64().to_le_bytes();
            let take = (buf.len() - i).min(bytes.len());
            buf[i..i + take].copy_from_slice(&bytes[..take]);
            i += take;
        }
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        for i in (1..items.len()).rev() {
            let j = self.next_usize(i + 1);
            items.swap(i, j);
        }
    }
}

fn fill_block_samples<C: BlockCipher>(cipher: &C, rng: &mut SplitMix64, out: &mut [u8]) {
    // Each sample intentionally concatenates multiple blocks under one random
    // key. That keeps the class distribution tied to the primitive itself
    // instead of to per-block key churn, which is fine for this distinguisher
    // experiment because the key is never exposed to the model.
    let mut block = vec![0u8; C::BLOCK_LEN];
    let mut written = 0usize;
    while written < out.len() {
        rng.fill(&mut block);
        cipher.encrypt(&mut block);
        let take = (out.len() - written).min(block.len());
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
    }
}

fn gen_aes128(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    let cipher = Aes128::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_aes256(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let cipher = Aes256::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_des(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 8];
    rng.fill(&mut key);
    let cipher = Des::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_tdes3(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 24];
    rng.fill(&mut key);
    let cipher = TripleDes::new_3key(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_simon128_128(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    let cipher = Simon128_128::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_speck128_128(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    let cipher = Speck128_128::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_magma(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let cipher = Magma::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_grasshopper(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let cipher = Grasshopper::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_sm4(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    let cipher = Sm4::new(&key);
    fill_block_samples(&cipher, rng, out);
}

fn gen_zuc128(rng: &mut SplitMix64, out: &mut [u8]) {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    rng.fill(&mut key);
    rng.fill(&mut iv);
    let mut cipher = Zuc128::new(&key, &iv);
    cipher.fill(out);
}

fn gen_random(rng: &mut SplitMix64, out: &mut [u8]) {
    rng.fill(out);
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                let value = args.next().ok_or("missing value for --output")?;
                cfg.output = PathBuf::from(value);
            }
            "--sample-len" => {
                let value = args
                    .next()
                    .ok_or("missing value for --sample-len")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --sample-len")?;
                if value == 0 {
                    return Err("--sample-len must be greater than zero".to_string());
                }
                cfg.sample_len = value;
            }
            "--train-per-class" => {
                let value = args
                    .next()
                    .ok_or("missing value for --train-per-class")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --train-per-class")?;
                cfg.train_per_class = value;
            }
            "--val-per-class" => {
                let value = args
                    .next()
                    .ok_or("missing value for --val-per-class")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --val-per-class")?;
                cfg.val_per_class = value;
            }
            "--test-per-class" => {
                let value = args
                    .next()
                    .ok_or("missing value for --test-per-class")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --test-per-class")?;
                cfg.test_per_class = value;
            }
            "--seed" => {
                let value = args
                    .next()
                    .ok_or("missing value for --seed")?
                    .parse::<u64>()
                    .map_err(|_| "invalid integer for --seed")?;
                cfg.seed = Some(value);
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument: {arg}\n\n{}", usage()));
            }
        }
    }

    Ok(cfg)
}

fn usage() -> String {
    format!(
        "Usage: cargo run --release --bin gen_ml_dataset -- [options]\n\
         \n\
         Options:\n\
           --output PATH             Output directory (default: ml/data)\n\
           --sample-len N            Bytes per sample (default: {DEFAULT_SAMPLE_LEN})\n\
           --train-per-class N       Train samples per class (default: 20000)\n\
           --val-per-class N         Validation samples per class (default: 4000)\n\
           --test-per-class N        Test samples per class (default: 4000)\n\
           --seed N                  Optional fixed 64-bit seed\n\
           --help                    Show this help\n\
         \n\
         Dataset classes: {}\n\
         Sample format: raw N-byte outputs only (no IVs, no labels in-band).",
        CIPHERS
            .iter()
            .map(|c| c.name)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn write_split(
    dir: &Path,
    split_name: &str,
    sample_len: usize,
    per_class: usize,
    rng: &mut SplitMix64,
) -> io::Result<usize> {
    let total = per_class * CIPHERS.len();
    let samples_path = dir.join(format!("{split_name}_samples.bin"));
    let labels_path = dir.join(format!("{split_name}_labels.bin"));
    let mut samples_file = File::create(samples_path)?;
    let mut labels_file = File::create(labels_path)?;

    let mut labels = Vec::with_capacity(total);
    for label in 0..CIPHERS.len() {
        labels.extend(std::iter::repeat(label as u8).take(per_class));
    }
    rng.shuffle(&mut labels);

    let mut sample = vec![0u8; sample_len];
    for &label in &labels {
        (CIPHERS[label as usize].generate)(rng, &mut sample);
        samples_file.write_all(&sample)?;
        labels_file.write_all(&[label])?;
    }

    Ok(total)
}

fn write_manifest(
    dir: &Path,
    cfg: &Config,
    seed: u64,
    train_total: usize,
    val_total: usize,
    test_total: usize,
) -> io::Result<()> {
    let classes = CIPHERS
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        "{{\n  \"sample_len\": {},\n  \"seed\": {seed},\n  \"classes\": [{classes}],\n  \
         \"train_per_class\": {},\n  \"val_per_class\": {},\n  \"test_per_class\": {},\n  \
         \"train_samples\": {train_total},\n  \"val_samples\": {val_total},\n  \
         \"test_samples\": {test_total}\n}}\n",
        cfg.sample_len, cfg.train_per_class, cfg.val_per_class, cfg.test_per_class
    );
    fs::write(dir.join("manifest.json"), manifest)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("{msg}");
            if msg.starts_with("Usage:") {
                return Ok(());
            }
            std::process::exit(2);
        }
    };

    let mut rng = match cfg.seed {
        Some(seed) => SplitMix64::from_seed(seed),
        None => SplitMix64::from_os()?,
    };
    let seed = rng.state;

    fs::create_dir_all(&cfg.output)?;
    let train_total = write_split(
        &cfg.output,
        "train",
        cfg.sample_len,
        cfg.train_per_class,
        &mut rng,
    )?;
    let val_total = write_split(
        &cfg.output,
        "val",
        cfg.sample_len,
        cfg.val_per_class,
        &mut rng,
    )?;
    let test_total = write_split(
        &cfg.output,
        "test",
        cfg.sample_len,
        cfg.test_per_class,
        &mut rng,
    )?;
    write_manifest(&cfg.output, &cfg, seed, train_total, val_total, test_total)?;

    println!(
        "wrote dataset to {} ({} classes, {}-byte samples, {} total rows)",
        cfg.output.display(),
        CIPHERS.len(),
        cfg.sample_len,
        train_total + val_total + test_total
    );

    Ok(())
}
