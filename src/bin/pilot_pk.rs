/// Public-key latency benchmark for pilot-bench.
///
/// Usage: pilot_pk <operation>
///
/// Performs the named operation N times and prints ms/op to stdout.
/// Pilot-bench calls this repeatedly until statistical confidence is reached.
///
/// EC / Edwards (fast; N = 500–1000):
///   ecdsa_keygen, ecdsa_sign, ecdsa_verify
///   ecdh_keygen, ecdh_agree, ecdh_serialize
///   ecies_keygen, ecies_encrypt, ecies_decrypt
///   ec_elgamal_keygen, ec_elgamal_encrypt, ec_elgamal_decrypt
///   ed25519_keygen, ed25519_sign, ed25519_verify
///   edwards_dh_keygen, edwards_dh_agree, edwards_dh_serialize
///   edwards_elgamal_keygen, edwards_elgamal_encrypt, edwards_elgamal_decrypt
///
/// Integer-arithmetic (slow; N = 3–100):
///   dsa_sign_1024, dsa_verify_1024
///   elgamal_encrypt_1024, elgamal_decrypt_1024
///   paillier_encrypt_1024, paillier_decrypt_1024
///   rsa_keygen_1024, rsa_decrypt_1024, rsa_sign_1024, rsa_verify_1024
///   rsa_keygen_2048, rsa_decrypt_2048, rsa_sign_2048, rsa_verify_2048
use std::hint::black_box;
use std::time::Instant;

use cryptography::public_key::ec::p256;
use cryptography::public_key::ec_edwards::ed25519 as ed25519_curve;
use cryptography::{
    CtrDrbgAes256, Dsa, EcElGamal, Ecdh, Ecdsa, Ecies, Ed25519, EdwardsDh, EdwardsElGamal, ElGamal,
    Paillier, Rsa, RsaOaep, RsaPss, Sha256,
};

const MSG: [u8; 32] = [0x42; 32];
const EC_MSG: [u8; 16] = [0x24; 16];
const OAEP_LABEL: &[u8] = b"pilot-pk-oaep";
const OAEP_SEED: [u8; 32] = [0x11; 32];
const PSS_SALT: [u8; 32] = [0x22; 32];

fn ms_per_op(elapsed: std::time::Duration, n: usize) -> f64 {
    elapsed.as_secs_f64() * 1000.0 / n as f64
}

fn main() {
    let op = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pilot_pk <operation>");
        std::process::exit(1);
    });

    let mut rng = CtrDrbgAes256::new(&[0x5a; 48]);

    let ms: f64 = match op.to_ascii_lowercase().as_str() {
        // ── ECDSA (P-256) ─────────────────────────────────────────────────────
        "ecdsa_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecdsa::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdsa_sign" => {
            let (_, priv_key) = Ecdsa::generate(p256(), &mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(
                    priv_key
                        .sign_message_bytes::<Sha256, _>(&MSG, &mut rng)
                        .unwrap(),
                );
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdsa_verify" => {
            let (pub_key, priv_key) = Ecdsa::generate(p256(), &mut rng);
            let sig = priv_key
                .sign_message_bytes::<Sha256, _>(&MSG, &mut rng)
                .unwrap();
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.verify_message_bytes::<Sha256>(&MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ECDH (P-256) ──────────────────────────────────────────────────────
        "ecdh_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecdh::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdh_agree" => {
            let (pub_a, _) = Ecdh::generate(p256(), &mut rng);
            let (_, priv_b) = Ecdh::generate(p256(), &mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdh_serialize" => {
            let (pub_key, _) = Ecdh::generate(p256(), &mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.to_bytes());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ECIES (P-256) ─────────────────────────────────────────────────────
        "ecies_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecies::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecies_encrypt" => {
            let (pub_key, _) = Ecies::generate(p256(), &mut rng);
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecies_decrypt" => {
            let (pub_key, priv_key) = Ecies::generate(p256(), &mut rng);
            let ct = pub_key.encrypt(&MSG, &mut rng);
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── EC ElGamal (P-256) ────────────────────────────────────────────────
        "ec_elgamal_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EcElGamal::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ec_elgamal_encrypt" => {
            let (pub_key, _) = EcElGamal::generate(p256(), &mut rng);
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&EC_MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ec_elgamal_decrypt" => {
            let (pub_key, priv_key) = EcElGamal::generate(p256(), &mut rng);
            let ct = pub_key.encrypt(&EC_MSG, &mut rng).unwrap();
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Ed25519 ───────────────────────────────────────────────────────────
        "ed25519_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ed25519::generate(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ed25519_sign" => {
            let (_, priv_key) = Ed25519::generate(&mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.sign_message_bytes(&MSG));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ed25519_verify" => {
            let (pub_key, priv_key) = Ed25519::generate(&mut rng);
            let sig = priv_key.sign_message_bytes(&MSG);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.verify_message_bytes(&MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Edwards DH (Ed25519 curve) ────────────────────────────────────────
        "edwards_dh_agree" => {
            let (pub_a, _) = EdwardsDh::generate(ed25519_curve(), &mut rng);
            let (_, priv_b) = EdwardsDh::generate(ed25519_curve(), &mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_dh_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EdwardsDh::generate(ed25519_curve(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_dh_serialize" => {
            let (pub_key, _) = EdwardsDh::generate(ed25519_curve(), &mut rng);
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.to_bytes());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Edwards ElGamal (Ed25519 curve) ───────────────────────────────────
        "edwards_elgamal_keygen" => {
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EdwardsElGamal::generate(ed25519_curve(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_elgamal_encrypt" => {
            let (pub_key, _) = EdwardsElGamal::generate(ed25519_curve(), &mut rng);
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt_int(7, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_elgamal_decrypt" => {
            let (pub_key, priv_key) = EdwardsElGamal::generate(ed25519_curve(), &mut rng);
            let ct = pub_key.encrypt_int(7, &mut rng);
            let n = 500;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt_int(&ct, 32).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── DSA (1024-bit) ────────────────────────────────────────────────────
        "dsa_sign_1024" => {
            let (_, priv_key) = Dsa::generate(&mut rng, 1024).unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(
                    priv_key
                        .sign_message_bytes::<Sha256, _>(&MSG, &mut rng)
                        .unwrap(),
                );
            }
            ms_per_op(t0.elapsed(), n)
        }
        "dsa_verify_1024" => {
            let (pub_key, priv_key) = Dsa::generate(&mut rng, 1024).unwrap();
            let sig = priv_key
                .sign_message_bytes::<Sha256, _>(&MSG, &mut rng)
                .unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.verify_message_bytes::<Sha256>(&MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ElGamal (1024-bit) ────────────────────────────────────────────────
        "elgamal_encrypt_1024" => {
            let (pub_key, _) = ElGamal::generate(&mut rng, 1024).unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "elgamal_decrypt_1024" => {
            let (pub_key, priv_key) = ElGamal::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Paillier (1024-bit) ───────────────────────────────────────────────
        "paillier_encrypt_1024" => {
            let (pub_key, _) = Paillier::generate(&mut rng, 1024).unwrap();
            let n = 30;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "paillier_decrypt_1024" => {
            let (pub_key, priv_key) = Paillier::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let n = 30;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── RSA (1024-bit) ────────────────────────────────────────────────────
        "rsa_keygen_1024" => {
            let n = 10;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Rsa::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_decrypt_1024" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let ct = RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaOaep::<Sha256>::decrypt(&priv_key, OAEP_LABEL, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_sign_1024" => {
            let (_, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let n = 100;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_verify_1024" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let sig = RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap();
            let n = 1000;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::verify(&pub_key, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── RSA (2048-bit) ────────────────────────────────────────────────────
        "rsa_keygen_2048" => {
            let n = 3;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Rsa::generate(&mut rng, 2048).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_decrypt_2048" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let ct = RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap();
            let n = 20;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaOaep::<Sha256>::decrypt(&priv_key, OAEP_LABEL, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_sign_2048" => {
            let (_, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let n = 20;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_verify_2048" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let sig = RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap();
            let n = 200;
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::verify(&pub_key, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        _ => {
            eprintln!("unknown operation: {}", op);
            std::process::exit(1);
        }
    };

    println!("{:.6}", ms);
}
