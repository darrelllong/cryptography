use std::io::{self, Write};
use std::time::{Duration, Instant};

use cryptography::{
    CtrDrbgAes256, ElGamal, Paillier, Rsa, RsaOaep, RsaPss, Sha256,
};
use cryptography::public_key::bigint::BigUint;

const MESSAGE: [u8; 32] = [0x42; 32];
const OAEP_LABEL: &[u8] = b"cryptography-rsa-oaep";
const OAEP_SEED: [u8; 32] = [0x11; 32];
const PSS_SALT: [u8; 32] = [0x22; 32];

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

fn main() {
    let bits = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048);
    let mut rng = CtrDrbgAes256::new(&[0x5a; 48]);

    println!("Public-key latency (teaching backend, {bits}-bit keys)");
    println!();

    announce("Generating RSA key");
    let start = Instant::now();
    let (rsa_public, rsa_private) = Rsa::generate(&mut rng, bits).expect("RSA key generation");
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

    announce("Generating ElGamal key");
    let start = Instant::now();
    let (elgamal_public, elgamal_private) =
        ElGamal::generate(&mut rng, bits).expect("ElGamal key generation");
    let elgamal_keygen = start.elapsed();

    announce("Measuring ElGamal");
    let start = Instant::now();
    let elgamal_ciphertext = elgamal_public
        .encrypt(&MESSAGE, &mut rng)
        .expect("ElGamal encrypt");
    let elgamal_encrypt = start.elapsed();

    let start = Instant::now();
    let elgamal_plaintext = elgamal_private.decrypt(&elgamal_ciphertext);
    let elgamal_decrypt = start.elapsed();
    assert_eq!(elgamal_plaintext, MESSAGE);

    announce("Generating Paillier key");
    let start = Instant::now();
    let (paillier_public, paillier_private) =
        Paillier::generate(&mut rng, bits).expect("Paillier key generation");
    let paillier_keygen = start.elapsed();

    announce("Measuring Paillier");
    let start = Instant::now();
    let paillier_ciphertext = paillier_public
        .encrypt(&MESSAGE, &mut rng)
        .expect("Paillier encrypt");
    let paillier_encrypt = start.elapsed();

    let start = Instant::now();
    let paillier_plaintext = paillier_private.decrypt(&paillier_ciphertext);
    let paillier_decrypt = start.elapsed();
    assert_eq!(paillier_plaintext, MESSAGE);

    let start = Instant::now();
    let rerandomized = paillier_public
        .rerandomize(&paillier_ciphertext, &mut rng)
        .expect("Paillier rerandomize");
    let paillier_rerandomize = start.elapsed();
    assert_eq!(paillier_private.decrypt(&rerandomized), MESSAGE);

    let other_ciphertext = paillier_public
        .encrypt(&[0x01], &mut rng)
        .expect("Paillier second encrypt");
    let start = Instant::now();
    let combined = paillier_public.add_ciphertexts(&paillier_ciphertext, &other_ciphertext);
    let paillier_add = start.elapsed();
    let combined_plaintext = paillier_private.decrypt(&combined);
    let mut expected = BigUint::from_be_bytes(&MESSAGE);
    expected = expected.add_ref(&BigUint::from_u64(1));
    assert_eq!(combined_plaintext, expected.to_be_bytes());

    println!("RSA");
    print_row("keygen", rsa_keygen);
    print_row("oaep encrypt", rsa_encrypt);
    print_row("oaep decrypt", rsa_decrypt);
    print_row("pss sign", rsa_sign);
    print_row("pss verify", rsa_verify_time);
    println!();

    println!("ElGamal");
    print_row("keygen", elgamal_keygen);
    print_row("encrypt", elgamal_encrypt);
    print_row("decrypt", elgamal_decrypt);
    println!();

    println!("Paillier");
    print_row("keygen", paillier_keygen);
    print_row("encrypt", paillier_encrypt);
    print_row("decrypt", paillier_decrypt);
    print_row("rerandomize", paillier_rerandomize);
    print_row("add ciphertexts", paillier_add);
}
