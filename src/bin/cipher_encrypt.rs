//! Randomness-battery driver for `scripts/cipher_randomness.R`.
//!
//! Usage: `cipher_encrypt <name> < plaintext > ciphertext`
//!
//! Reads all of standard input, encrypts it under the named cipher, and
//! writes the raw ciphertext (exactly as many bytes as were read) to standard
//! output. Block ciphers run in SP 800-38A CTR mode; stream ciphers run in
//! their native keystream mode. The key and the IV / nonce are drawn fresh
//! from the operating system (`/dev/urandom`) on every run, as the R battery
//! requires, and are never emitted: nobody can decrypt the output, including
//! the caller, so it is fit for statistical analysis only.
//!
//! The crate itself provides no entropy source (see the crate docs); this
//! binary is the only place that reads the OS pool, and it does so because a
//! fixed DRBG seed would make every run of the battery identical.
//!
//! With no argument, or an unknown name, the supported names are listed on
//! standard error and the process exits with status 2.
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use cryptography::chacha20::{ChaCha20, XChaCha20};
use cryptography::rabbit::Rabbit;
use cryptography::salsa20::Salsa20;
use cryptography::{
    Aes128, Aes192, Aes256, BlockCipher, Camellia128, Camellia192, Camellia256, Cast128, Ctr, Des,
    Grasshopper, Magma, Present128, Present80, Seed, Serpent128, Serpent192, Serpent256,
    Simon128_128, Simon128_256, Simon32_64, Simon64_128, Sm4, Snow3g, Speck128_128, Speck128_256,
    Speck32_64, Speck64_128, StreamCipher, TripleDes, Twofish128, Twofish256, Zuc128,
};

/// The names the R battery's `CIPHERS` vector may pass, in its order.
const NAMES: [&str; 34] = [
    "aes128",
    "aes192",
    "aes256",
    "camellia128",
    "camellia192",
    "camellia256",
    "cast128",
    "des",
    "3des",
    "grasshopper",
    "magma",
    "present80",
    "present128",
    "seed",
    "serpent128",
    "serpent192",
    "serpent256",
    "sm4",
    "twofish128",
    "twofish256",
    "simon32_64",
    "simon64_128",
    "simon128_128",
    "simon128_256",
    "speck32_64",
    "speck64_128",
    "speck128_128",
    "speck128_256",
    "chacha20",
    "xchacha20",
    "salsa20",
    "rabbit",
    "zuc128",
    "snow3g",
];

/// Fill `buf` from the operating system's entropy pool.
fn fill_os_random(buf: &mut [u8]) {
    let result = File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf));
    if let Err(err) = result {
        eprintln!("cipher_encrypt: cannot read /dev/urandom: {err}");
        std::process::exit(1);
    }
}

/// A fresh OS-random array; the length is inferred from the constructor
/// parameter it is passed to.
fn os_random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_os_random(&mut out);
    out
}

/// Retry `build` with fresh key material until the constructor accepts it.
/// Only DES-family constructors can refuse (weak or repeated components),
/// with probability about 2^-52 per draw.
fn keyed<T>(mut build: impl FnMut() -> Option<T>) -> T {
    loop {
        if let Some(cipher) = build() {
            return cipher;
        }
    }
}

/// Encrypt `data` in place under `cipher` in CTR mode with a fresh random
/// initial counter block.
fn ctr<C: BlockCipher>(cipher: C, data: &mut [u8]) {
    let mut iv = vec![0u8; C::BLOCK_LEN];
    fill_os_random(&mut iv);
    Ctr::new(cipher).apply_keystream(&iv, data);
}

/// Encrypt `data` in place with a stream cipher's native keystream.
fn stream<S: StreamCipher>(mut cipher: S, data: &mut [u8]) {
    cipher.fill(data);
}

/// Encrypt `data` in place under the named cipher; `false` if the name is
/// not one of [`NAMES`].
fn encrypt(name: &str, data: &mut [u8]) -> bool {
    match name {
        "aes128" => ctr(Aes128::new(&os_random()), data),
        "aes192" => ctr(Aes192::new(&os_random()), data),
        "aes256" => ctr(Aes256::new(&os_random()), data),
        "camellia128" => ctr(Camellia128::new(&os_random()), data),
        "camellia192" => ctr(Camellia192::new(&os_random()), data),
        "camellia256" => ctr(Camellia256::new(&os_random()), data),
        "cast128" => ctr(Cast128::new(&os_random()), data),
        "des" => ctr(keyed(|| Des::new(&os_random()).ok()), data),
        "3des" => ctr(keyed(|| TripleDes::new_3key(&os_random()).ok()), data),
        "grasshopper" => ctr(Grasshopper::new(&os_random()), data),
        "magma" => ctr(Magma::new(&os_random()), data),
        "present80" => ctr(Present80::new(&os_random()), data),
        "present128" => ctr(Present128::new(&os_random()), data),
        "seed" => ctr(Seed::new(&os_random()), data),
        "serpent128" => ctr(Serpent128::new(&os_random()), data),
        "serpent192" => ctr(Serpent192::new(&os_random()), data),
        "serpent256" => ctr(Serpent256::new(&os_random()), data),
        "sm4" => ctr(Sm4::new(&os_random()), data),
        "twofish128" => ctr(Twofish128::new(&os_random()), data),
        "twofish256" => ctr(Twofish256::new(&os_random()), data),
        "simon32_64" => ctr(Simon32_64::new(&os_random()), data),
        "simon64_128" => ctr(Simon64_128::new(&os_random()), data),
        "simon128_128" => ctr(Simon128_128::new(&os_random()), data),
        "simon128_256" => ctr(Simon128_256::new(&os_random()), data),
        "speck32_64" => ctr(Speck32_64::new(&os_random()), data),
        "speck64_128" => ctr(Speck64_128::new(&os_random()), data),
        "speck128_128" => ctr(Speck128_128::new(&os_random()), data),
        "speck128_256" => ctr(Speck128_256::new(&os_random()), data),
        "chacha20" => stream(ChaCha20::new(&os_random(), &os_random()), data),
        "xchacha20" => stream(XChaCha20::new(&os_random(), &os_random()), data),
        "salsa20" => stream(Salsa20::new(&os_random(), &os_random()), data),
        "rabbit" => stream(Rabbit::new(&os_random(), &os_random()), data),
        "zuc128" => stream(Zuc128::new(&os_random(), &os_random()), data),
        "snow3g" => stream(Snow3g::new(&os_random(), &os_random()), data),
        _ => return false,
    }
    true
}

fn usage() -> ExitCode {
    eprintln!("usage: cipher_encrypt <name> < plaintext > ciphertext");
    eprintln!("supported names:");
    for name in NAMES {
        eprintln!("  {name}");
    }
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let Some(name) = std::env::args().nth(1) else {
        return usage();
    };
    if !NAMES.contains(&name.as_str()) {
        eprintln!("cipher_encrypt: unknown cipher `{name}`");
        return usage();
    }

    let mut data = Vec::new();
    if let Err(err) = io::stdin().lock().read_to_end(&mut data) {
        eprintln!("cipher_encrypt: cannot read stdin: {err}");
        return ExitCode::from(1);
    }
    // `NAMES` and the match arms are checked against each other above; a
    // name that passes the first and fails the second is a programming error.
    assert!(
        encrypt(&name, &mut data),
        "`{name}` is listed but unhandled"
    );

    let mut out = io::stdout().lock();
    if let Err(err) = out.write_all(&data).and_then(|()| out.flush()) {
        eprintln!("cipher_encrypt: cannot write stdout: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
