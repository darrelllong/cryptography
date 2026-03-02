use std::io::{self, Write};
use std::time::{Duration, Instant};

use cryptography::public_key::bigint::BigUint;
use cryptography::{
    Cocks, CtrDrbgAes256, ElGamal, Paillier, Rabin, Rsa, RsaOaep, RsaPss, SchmidtSamoa, Sha256,
};

const MESSAGE: [u8; 32] = [0x42; 32];
const OAEP_LABEL: &[u8] = b"cryptography-rsa-oaep";
const OAEP_SEED: [u8; 32] = [0x11; 32];
const PSS_SALT: [u8; 32] = [0x22; 32];

type ElGamalTimings = (Duration, Duration, Duration);
type PaillierTimings = (Duration, Duration, Duration, Duration, Duration);
type RsaTimings = (Duration, Duration, Duration, Duration, Duration);
type SimplePkTimings = (Duration, Duration, Duration);

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_row(name: &str, duration: Duration) {
    println!("{name:<24} {:>10.3} ms", ms(duration));
}

fn announce(stage: &str) {
    println!("{stage}...");
    io::stdout().flush().expect("flush benchmark progress");
}

fn parse_args() -> (usize, bool) {
    let mut bits = 1024usize;
    let mut skip_elgamal = false;
    for arg in std::env::args().skip(1) {
        if arg == "--skip-elgamal" {
            skip_elgamal = true;
        } else if let Ok(parsed) = arg.parse::<usize>() {
            bits = parsed;
        }
    }
    (bits, skip_elgamal)
}

fn bench_rsa(
    rng: &mut CtrDrbgAes256,
    bits: usize,
) -> (
    cryptography::RsaPublicKey,
    cryptography::RsaPrivateKey,
    RsaTimings,
) {
    announce("Generating RSA key");
    let start = Instant::now();
    let (rsa_public, rsa_private) = Rsa::generate(rng, bits).expect("RSA key generation");
    let rsa_keygen = start.elapsed();

    announce("Measuring RSA OAEP/PSS");
    let start = Instant::now();
    let rsa_ciphertext =
        RsaOaep::<Sha256>::encrypt(&rsa_public, OAEP_LABEL, &MESSAGE, &OAEP_SEED).expect("OAEP");
    let rsa_encrypt = start.elapsed();

    let start = Instant::now();
    let rsa_plaintext =
        RsaOaep::<Sha256>::decrypt(&rsa_private, OAEP_LABEL, &rsa_ciphertext).expect("OAEP");
    let rsa_decrypt = start.elapsed();
    assert_eq!(rsa_plaintext, MESSAGE);

    let start = Instant::now();
    let rsa_signature = RsaPss::<Sha256>::sign(&rsa_private, &MESSAGE, &PSS_SALT).expect("PSS");
    let rsa_sign = start.elapsed();

    let start = Instant::now();
    let rsa_verify = RsaPss::<Sha256>::verify(&rsa_public, &MESSAGE, &rsa_signature);
    let rsa_verify_time = start.elapsed();
    assert!(rsa_verify);

    (
        rsa_public,
        rsa_private,
        (
            rsa_keygen,
            rsa_encrypt,
            rsa_decrypt,
            rsa_sign,
            rsa_verify_time,
        ),
    )
}

fn bench_elgamal(rng: &mut CtrDrbgAes256, bits: usize) -> ElGamalTimings {
    announce("Generating ElGamal key");
    let start = Instant::now();
    let (elgamal_public, elgamal_private) =
        ElGamal::generate(rng, bits).expect("ElGamal key generation");
    let elgamal_keygen = start.elapsed();

    announce("Measuring ElGamal");
    let start = Instant::now();
    let elgamal_ciphertext = elgamal_public
        .encrypt(&MESSAGE, rng)
        .expect("ElGamal encrypt");
    let elgamal_encrypt = start.elapsed();

    let start = Instant::now();
    let elgamal_plaintext = elgamal_private.decrypt(&elgamal_ciphertext);
    let elgamal_decrypt = start.elapsed();
    assert_eq!(elgamal_plaintext, MESSAGE);

    (elgamal_keygen, elgamal_encrypt, elgamal_decrypt)
}

fn bench_paillier(rng: &mut CtrDrbgAes256, bits: usize) -> PaillierTimings {
    announce("Generating Paillier key");
    let start = Instant::now();
    let (paillier_public, paillier_private) =
        Paillier::generate(rng, bits).expect("Paillier key generation");
    let paillier_keygen = start.elapsed();

    announce("Measuring Paillier");
    let start = Instant::now();
    let paillier_ciphertext = paillier_public
        .encrypt(&MESSAGE, rng)
        .expect("Paillier encrypt");
    let paillier_encrypt = start.elapsed();

    let start = Instant::now();
    let paillier_plaintext = paillier_private.decrypt(&paillier_ciphertext);
    let paillier_decrypt = start.elapsed();
    assert_eq!(paillier_plaintext, MESSAGE);

    let start = Instant::now();
    let rerandomized = paillier_public
        .rerandomize(&paillier_ciphertext, rng)
        .expect("Paillier rerandomize");
    let paillier_rerandomize = start.elapsed();
    assert_eq!(paillier_private.decrypt(&rerandomized), MESSAGE);

    let other_ciphertext = paillier_public
        .encrypt(&[0x01], rng)
        .expect("Paillier second encrypt");
    let start = Instant::now();
    let combined = paillier_public
        .add_ciphertexts(&paillier_ciphertext, &other_ciphertext)
        .expect("Paillier ciphertexts are in range");
    let paillier_add = start.elapsed();
    let combined_plaintext = paillier_private.decrypt(&combined);
    let mut expected = BigUint::from_be_bytes(&MESSAGE);
    expected = expected.add_ref(&BigUint::from_u64(1));
    assert_eq!(combined_plaintext, expected.to_be_bytes());

    (
        paillier_keygen,
        paillier_encrypt,
        paillier_decrypt,
        paillier_rerandomize,
        paillier_add,
    )
}

fn bench_cocks(rng: &mut CtrDrbgAes256, bits: usize) -> SimplePkTimings {
    announce("Generating Cocks key");
    let start = Instant::now();
    let (public, private) = Cocks::generate(rng, bits).expect("Cocks key generation");
    let keygen = start.elapsed();

    announce("Measuring Cocks");
    let start = Instant::now();
    let ciphertext = public.encrypt(&MESSAGE).expect("Cocks encrypt");
    let encrypt = start.elapsed();

    let start = Instant::now();
    let plaintext = private.decrypt(&ciphertext);
    let decrypt = start.elapsed();
    assert_eq!(plaintext, MESSAGE);

    (keygen, encrypt, decrypt)
}

fn bench_rabin(rng: &mut CtrDrbgAes256, bits: usize) -> SimplePkTimings {
    announce("Generating Rabin key");
    let start = Instant::now();
    let (public, private) = Rabin::generate(rng, bits).expect("Rabin key generation");
    let keygen = start.elapsed();

    announce("Measuring Rabin");
    let start = Instant::now();
    let ciphertext = public.encrypt(&MESSAGE).expect("Rabin encrypt");
    let encrypt = start.elapsed();

    let start = Instant::now();
    let plaintext = private.decrypt(&ciphertext).expect("Rabin decrypt");
    let decrypt = start.elapsed();
    assert_eq!(plaintext, MESSAGE);

    (keygen, encrypt, decrypt)
}

fn bench_schmidt_samoa(rng: &mut CtrDrbgAes256, bits: usize) -> SimplePkTimings {
    announce("Generating Schmidt-Samoa key");
    let start = Instant::now();
    let (public, private) =
        SchmidtSamoa::generate(rng, bits).expect("Schmidt-Samoa key generation");
    let keygen = start.elapsed();

    announce("Measuring Schmidt-Samoa");
    let start = Instant::now();
    let ciphertext = public.encrypt(&MESSAGE).expect("Schmidt-Samoa encrypt");
    let encrypt = start.elapsed();

    let start = Instant::now();
    let plaintext = private.decrypt(&ciphertext);
    let decrypt = start.elapsed();
    assert_eq!(plaintext, MESSAGE);

    (keygen, encrypt, decrypt)
}

fn main() {
    let (bits, skip_elgamal) = parse_args();
    if bits < 528 {
        eprintln!("RSAES-OAEP with SHA-256 requires at least a 528-bit modulus.");
        std::process::exit(2);
    }
    let mut rng = CtrDrbgAes256::new(&[0x5a; 48]);

    println!("Public-key latency (teaching backend, {bits}-bit keys)");
    println!();

    let (_, _, (rsa_keygen, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify_time)) =
        bench_rsa(&mut rng, bits);

    let mut elgamal_timings = None;
    if skip_elgamal {
        println!("Skipping ElGamal benchmark.");
        println!();
    } else {
        elgamal_timings = Some(bench_elgamal(&mut rng, bits));
    }

    let (paillier_keygen, paillier_encrypt, paillier_decrypt, paillier_rerandomize, paillier_add) =
        bench_paillier(&mut rng, bits);
    let (cocks_keygen, cocks_encrypt, cocks_decrypt) = bench_cocks(&mut rng, bits);
    let (rabin_keygen, rabin_encrypt, rabin_decrypt) = bench_rabin(&mut rng, bits);
    let (schmidt_keygen, schmidt_encrypt, schmidt_decrypt) = bench_schmidt_samoa(&mut rng, bits);

    println!("RSA");
    print_row("keygen", rsa_keygen);
    print_row("oaep encrypt", rsa_encrypt);
    print_row("oaep decrypt", rsa_decrypt);
    print_row("pss sign", rsa_sign);
    print_row("pss verify", rsa_verify_time);
    println!();

    if let Some((elgamal_keygen, elgamal_encrypt, elgamal_decrypt)) = elgamal_timings {
        println!("ElGamal");
        print_row("keygen", elgamal_keygen);
        print_row("encrypt", elgamal_encrypt);
        print_row("decrypt", elgamal_decrypt);
        println!();
    }

    println!("Paillier");
    print_row("keygen", paillier_keygen);
    print_row("encrypt", paillier_encrypt);
    print_row("decrypt", paillier_decrypt);
    print_row("rerandomize", paillier_rerandomize);
    print_row("add ciphertexts", paillier_add);
    println!();

    println!("Cocks");
    print_row("keygen", cocks_keygen);
    print_row("encrypt", cocks_encrypt);
    print_row("decrypt", cocks_decrypt);
    println!();

    println!("Rabin");
    print_row("keygen", rabin_keygen);
    print_row("encrypt", rabin_encrypt);
    print_row("decrypt", rabin_decrypt);
    println!();

    println!("Schmidt-Samoa");
    print_row("keygen", schmidt_keygen);
    print_row("encrypt", schmidt_encrypt);
    print_row("decrypt", schmidt_decrypt);
}
