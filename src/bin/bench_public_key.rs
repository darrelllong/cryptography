use std::io::{self, Write};
use std::time::{Duration, Instant};

use cryptography::public_key::ec_edwards::ed25519 as edwards25519_curve;
use cryptography::vt::{
    p256, BigUint, Cocks, Dsa, EcElGamal, Ecdh, EcdhPublicKey, Ecdsa, Ecies, Ed25519, EdwardsDh,
    EdwardsDhPublicKey, EdwardsElGamal, ElGamal, Paillier, Rabin, Rsa, RsaOaep, RsaPrivateKey,
    RsaPss, RsaPublicKey, SchmidtSamoa,
};
use cryptography::{CtrDrbgAes256, Sha256};

const MESSAGE: [u8; 32] = [0x42; 32];
const EC_MESSAGE: [u8; 16] = [0x24; 16];
const OAEP_LABEL: &[u8] = b"cryptography-rsa-oaep";
const OAEP_SEED: [u8; 32] = [0x11; 32];
const PSS_SALT: [u8; 32] = [0x22; 32];

type ElGamalTimings = (Duration, Duration, Duration);
type DsaTimings = (Duration, Duration, Duration);
type PaillierTimings = (Duration, Duration, Duration, Duration, Duration);
type RsaTimings = (Duration, Duration, Duration, Duration, Duration);
type SimplePkTimings = (Duration, Duration, Duration);
type EcdhTimings = (Duration, Duration, Duration);
type EdwardsDhTimings = (Duration, Duration, Duration);
type EcdsaTimings = (Duration, Duration, Duration);
type Ed25519Timings = (Duration, Duration, Duration);
type EciesTimings = (Duration, Duration, Duration);
type EcElGamalTimings = (Duration, Duration, Duration);
type EdwardsElGamalTimings = (Duration, Duration, Duration);

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

fn print_triplet(section: &str, labels: [&str; 3], timings: (Duration, Duration, Duration)) {
    let (first, second, third) = timings;
    println!("{section}");
    print_row(labels[0], first);
    print_row(labels[1], second);
    print_row(labels[2], third);
    println!();
}

fn print_quintet(section: &str, labels: [&str; 5], timings: PaillierTimings) {
    let (first, second, third, fourth, fifth) = timings;
    println!("{section}");
    print_row(labels[0], first);
    print_row(labels[1], second);
    print_row(labels[2], third);
    print_row(labels[3], fourth);
    print_row(labels[4], fifth);
    println!();
}

fn print_ec_sections(
    p256_ecdh_timings: EcdhTimings,
    p256_ecdsa_timings: EcdsaTimings,
    edwards_dh_timings: EdwardsDhTimings,
    ed25519_timings: Ed25519Timings,
    p256_ecies_timings: EciesTimings,
    p256_elgamal_timings: EcElGamalTimings,
    edwards_elgamal_timings: EdwardsElGamalTimings,
) {
    print_triplet(
        "ECDH (P-256)",
        ["keygen", "agree", "serialize"],
        p256_ecdh_timings,
    );
    print_triplet(
        "ECDSA (P-256)",
        ["keygen", "sign", "verify"],
        p256_ecdsa_timings,
    );
    print_triplet(
        "Edwards DH (Ed25519)",
        ["keygen", "agree", "serialize"],
        edwards_dh_timings,
    );
    print_triplet("Ed25519", ["keygen", "sign", "verify"], ed25519_timings);
    print_triplet(
        "ECIES (P-256)",
        ["keygen", "encrypt", "decrypt"],
        p256_ecies_timings,
    );
    print_triplet(
        "EC ElGamal (P-256)",
        ["keygen", "encrypt", "decrypt"],
        p256_elgamal_timings,
    );
    print_triplet(
        "Edwards ElGamal (Ed25519)",
        ["keygen", "encrypt", "decrypt"],
        edwards_elgamal_timings,
    );
}

fn parse_args() -> (usize, bool, bool) {
    let mut bits = 1024usize;
    let mut skip_elgamal = false;
    let mut skip_dsa = false;
    for arg in std::env::args().skip(1) {
        if arg == "--skip-elgamal" {
            skip_elgamal = true;
        } else if arg == "--skip-dsa" {
            skip_dsa = true;
        } else if let Ok(parsed) = arg.parse::<usize>() {
            bits = parsed;
        }
    }
    (bits, skip_elgamal, skip_dsa)
}

fn bench_rsa(rng: &mut CtrDrbgAes256, bits: usize) -> (RsaPublicKey, RsaPrivateKey, RsaTimings) {
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

fn bench_dsa(rng: &mut CtrDrbgAes256, bits: usize) -> DsaTimings {
    announce("Generating DSA key");
    let start = Instant::now();
    let (public, private) = Dsa::generate(rng, bits).expect("DSA key generation");
    let keygen = start.elapsed();

    announce("Measuring DSA");
    let start = Instant::now();
    // Use the message-level API so the benchmark follows the same hashing path
    // a normal caller would take.
    let signature = private
        .sign_message_bytes::<Sha256>(&MESSAGE)
        .expect("DSA sign");
    let sign = start.elapsed();

    let start = Instant::now();
    let verified = public.verify_message_bytes::<Sha256>(&MESSAGE, &signature);
    let verify = start.elapsed();
    assert!(verified);

    (keygen, sign, verify)
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

fn bench_ecdh(rng: &mut CtrDrbgAes256) -> EcdhTimings {
    announce("Generating ECDH key");
    let start = Instant::now();
    let (public_a, private_a) = Ecdh::generate(p256(), rng);
    let keygen = start.elapsed();

    announce("Measuring ECDH");
    let (public_b, private_b) = Ecdh::generate(p256(), rng);
    let start = Instant::now();
    let shared_a = private_a
        .agree_x_coordinate(&public_b)
        .expect("ECDH agree A");
    let shared_b = private_b
        .agree_x_coordinate(&public_a)
        .expect("ECDH agree B");
    let agree = start.elapsed();
    assert_eq!(shared_a, shared_b);
    assert_eq!(shared_a.len(), 32);

    let start = Instant::now();
    let blob = public_a.to_key_blob();
    let recovered = EcdhPublicKey::from_key_blob(&blob).expect("ECDH public roundtrip");
    let serialize = start.elapsed();
    assert_eq!(recovered.to_wire_bytes(), public_a.to_wire_bytes());

    (keygen, agree, serialize)
}

fn bench_ecdsa(rng: &mut CtrDrbgAes256) -> EcdsaTimings {
    announce("Generating ECDSA key");
    let start = Instant::now();
    let (public, private) = Ecdsa::generate(p256(), rng);
    let keygen = start.elapsed();

    announce("Measuring ECDSA");
    let start = Instant::now();
    let signature = private
        .sign_message_bytes::<Sha256>(&MESSAGE)
        .expect("ECDSA sign");
    let sign = start.elapsed();

    let start = Instant::now();
    let verified = public.verify_message_bytes::<Sha256>(&MESSAGE, &signature);
    let verify = start.elapsed();
    assert!(verified);

    (keygen, sign, verify)
}

fn bench_edwards_dh(rng: &mut CtrDrbgAes256) -> EdwardsDhTimings {
    announce("Generating Edwards DH key");
    let start = Instant::now();
    let (public_a, private_a) = EdwardsDh::generate(edwards25519_curve(), rng);
    let keygen = start.elapsed();

    announce("Measuring Edwards DH");
    let (public_b, private_b) = EdwardsDh::generate(edwards25519_curve(), rng);
    let start = Instant::now();
    let shared_a = private_a
        .agree_compressed_point(&public_b)
        .expect("Edwards DH agree A");
    let shared_b = private_b
        .agree_compressed_point(&public_a)
        .expect("Edwards DH agree B");
    let agree = start.elapsed();
    assert_eq!(shared_a, shared_b);
    assert_eq!(shared_a.len(), 32);

    let start = Instant::now();
    let blob = public_a.to_key_blob();
    let recovered = EdwardsDhPublicKey::from_key_blob(&blob).expect("Edwards DH public roundtrip");
    let serialize = start.elapsed();
    assert_eq!(recovered.to_wire_bytes(), public_a.to_wire_bytes());

    (keygen, agree, serialize)
}

fn bench_ecies(rng: &mut CtrDrbgAes256) -> EciesTimings {
    announce("Generating ECIES key");
    let start = Instant::now();
    let (public, private) = Ecies::generate(p256(), rng);
    let keygen = start.elapsed();

    announce("Measuring ECIES");
    let start = Instant::now();
    let ciphertext = public.encrypt(&MESSAGE, rng);
    let encrypt = start.elapsed();

    let start = Instant::now();
    let plaintext = private.decrypt(&ciphertext).expect("ECIES decrypt");
    let decrypt = start.elapsed();
    assert_eq!(plaintext, MESSAGE);

    (keygen, encrypt, decrypt)
}

fn bench_edwards_elgamal(rng: &mut CtrDrbgAes256) -> EdwardsElGamalTimings {
    announce("Generating Edwards ElGamal key");
    let start = Instant::now();
    let (public, private) = EdwardsElGamal::generate(edwards25519_curve(), rng);
    let keygen = start.elapsed();

    announce("Measuring Edwards ElGamal");
    let start = Instant::now();
    let ciphertext = public.encrypt_int(7, rng);
    let encrypt = start.elapsed();

    let start = Instant::now();
    let message = private
        .decrypt_int(&ciphertext, 32)
        .expect("Edwards ElGamal decrypt");
    let decrypt = start.elapsed();
    assert_eq!(message, 7);

    (keygen, encrypt, decrypt)
}

fn bench_ed25519(rng: &mut CtrDrbgAes256) -> Ed25519Timings {
    announce("Generating Ed25519 key");
    let start = Instant::now();
    let (public, private) = Ed25519::generate(rng);
    let keygen = start.elapsed();

    announce("Measuring Ed25519");
    let start = Instant::now();
    let signature = private.sign_message_bytes(&MESSAGE);
    let sign = start.elapsed();

    let start = Instant::now();
    let verified = public.verify_message_bytes(&MESSAGE, &signature);
    let verify = start.elapsed();
    assert!(verified);

    (keygen, sign, verify)
}

fn bench_ec_elgamal(rng: &mut CtrDrbgAes256) -> EcElGamalTimings {
    announce("Generating EC ElGamal key");
    let start = Instant::now();
    let (public, private) = EcElGamal::generate(p256(), rng);
    let keygen = start.elapsed();

    announce("Measuring EC ElGamal");
    let start = Instant::now();
    let ciphertext = public
        .encrypt(&EC_MESSAGE, rng)
        .expect("EC ElGamal encrypt");
    let encrypt = start.elapsed();

    let start = Instant::now();
    let plaintext = private.decrypt(&ciphertext);
    let decrypt = start.elapsed();
    assert_eq!(plaintext, EC_MESSAGE);

    (keygen, encrypt, decrypt)
}

fn main() {
    let (bits, skip_elgamal, skip_dsa) = parse_args();
    if bits < 528 {
        eprintln!("RSAES-OAEP with SHA-256 requires at least a 528-bit modulus.");
        std::process::exit(2);
    }
    let mut rng = CtrDrbgAes256::new(&[0x5a; 48]);

    println!("Public-key latency (in-tree bigint backend, {bits}-bit keys)");
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

    let mut dsa_timings = None;
    if skip_dsa {
        println!("Skipping DSA benchmark.");
        println!();
    } else {
        dsa_timings = Some(bench_dsa(&mut rng, bits));
    }

    let paillier_timings = bench_paillier(&mut rng, bits);
    let cocks_timings = bench_cocks(&mut rng, bits);
    let rabin_timings = bench_rabin(&mut rng, bits);
    let schmidt_timings = bench_schmidt_samoa(&mut rng, bits);
    let (ecdh_keygen, ecdh_agree, ecdh_serialize) = bench_ecdh(&mut rng);
    let (edwards_dh_keygen, edwards_dh_agree, edwards_dh_serialize) = bench_edwards_dh(&mut rng);
    let (ecdsa_keygen, ecdsa_sign, ecdsa_verify) = bench_ecdsa(&mut rng);
    let (ed25519_keygen, ed25519_sign, ed25519_verify) = bench_ed25519(&mut rng);
    let (ecies_keygen, ecies_encrypt, ecies_decrypt) = bench_ecies(&mut rng);
    let (p256_elgamal_keygen, p256_elgamal_encrypt, p256_elgamal_decrypt) =
        bench_ec_elgamal(&mut rng);
    let (edwards_elgamal_keygen, edwards_elgamal_encrypt, edwards_elgamal_decrypt) =
        bench_edwards_elgamal(&mut rng);

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

    if let Some((dsa_keygen, dsa_sign, dsa_verify)) = dsa_timings {
        println!("DSA");
        print_row("keygen", dsa_keygen);
        print_row("sign", dsa_sign);
        print_row("verify", dsa_verify);
        println!();
    }

    print_quintet(
        "Paillier",
        [
            "keygen",
            "encrypt",
            "decrypt",
            "rerandomize",
            "add ciphertexts",
        ],
        paillier_timings,
    );
    print_triplet("Cocks", ["keygen", "encrypt", "decrypt"], cocks_timings);
    print_triplet("Rabin", ["keygen", "encrypt", "decrypt"], rabin_timings);
    print_triplet(
        "Schmidt-Samoa",
        ["keygen", "encrypt", "decrypt"],
        schmidt_timings,
    );
    print_ec_sections(
        (ecdh_keygen, ecdh_agree, ecdh_serialize),
        (ecdsa_keygen, ecdsa_sign, ecdsa_verify),
        (edwards_dh_keygen, edwards_dh_agree, edwards_dh_serialize),
        (ed25519_keygen, ed25519_sign, ed25519_verify),
        (ecies_keygen, ecies_encrypt, ecies_decrypt),
        (
            p256_elgamal_keygen,
            p256_elgamal_encrypt,
            p256_elgamal_decrypt,
        ),
        (
            edwards_elgamal_keygen,
            edwards_elgamal_encrypt,
            edwards_elgamal_decrypt,
        ),
    );
}
