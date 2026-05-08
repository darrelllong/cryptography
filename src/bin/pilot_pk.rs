/// Public-key latency benchmark for pilot-bench.
///
/// Usage: pilot_pk <operation>
///
/// Performs the named operation N times and prints ms/op to stdout.
/// Pilot-bench calls this repeatedly until statistical confidence is reached.
///
/// EC / Edwards (base N = 500–1000 before scaling):
///   ecdsa_keygen, ecdsa_sign, ecdsa_verify
///   ecdh_keygen, ecdh_agree, ecdh_serialize
///   ecies_keygen, ecies_encrypt, ecies_decrypt
///   ec_elgamal_keygen, ec_elgamal_encrypt, ec_elgamal_decrypt
///   ed25519_keygen, ed25519_sign, ed25519_verify
///   edwards_dh_keygen, edwards_dh_agree, edwards_dh_serialize
///   edwards_elgamal_keygen, edwards_elgamal_encrypt, edwards_elgamal_decrypt
///
/// Integer-arithmetic (base N = 3–5000 before scaling):
///   dsa_keygen_1024, dsa_sign_1024, dsa_verify_1024
///   elgamal_keygen_1024, elgamal_encrypt_1024, elgamal_decrypt_1024
///   paillier_keygen_1024, paillier_encrypt_1024, paillier_decrypt_1024
///   paillier_rerandomize_1024, paillier_add_1024
///   cocks_keygen_1024, cocks_encrypt_1024, cocks_decrypt_1024
///   rabin_keygen_1024, rabin_encrypt_1024, rabin_decrypt_1024
///   schmidt_samoa_keygen_1024, schmidt_samoa_encrypt_1024,
///   schmidt_samoa_decrypt_1024
///   rsa_keygen_1024, rsa_encrypt_1024, rsa_decrypt_1024, rsa_sign_1024,
///   rsa_verify_1024
///   rsa_keygen_2048, rsa_encrypt_2048, rsa_decrypt_2048, rsa_sign_2048,
///   rsa_verify_2048
///   mlkem512_keygen, mlkem512_encaps, mlkem512_decaps
///   mlkem768_keygen, mlkem768_encaps, mlkem768_decaps
///   mlkem1024_keygen, mlkem1024_encaps, mlkem1024_decaps
///   mldsa44_keygen, mldsa44_sign, mldsa44_verify
///   mldsa65_keygen, mldsa65_sign, mldsa65_verify
///   mldsa87_keygen, mldsa87_sign, mldsa87_verify
///   ntruhps509_keygen, ntruhps509_encaps, ntruhps509_decaps
///   ntruhps677_keygen, ntruhps677_encaps, ntruhps677_decaps
///   ntruhps821_keygen, ntruhps821_encaps, ntruhps821_decaps
///   ntruhrss701_keygen, ntruhrss701_encaps, ntruhrss701_decaps
///   ntruees401ep1_keygen, ntruees401ep1_encrypt, ntruees401ep1_decrypt
///   ntruees449ep1_keygen, ntruees449ep1_encrypt, ntruees449ep1_decrypt
///   ntruees677ep1_keygen, ntruees677ep1_encrypt, ntruees677ep1_decrypt
///   ntruees1087ep2_keygen, ntruees1087ep2_encrypt, ntruees1087ep2_decrypt
///
/// Iteration scaling: set `PILOT_PK_ITERS_PERCENT` (1..=100). Default: 25.
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use cryptography::public_key::ec_edwards::ed25519 as ed25519_curve;
use cryptography::vt::{
    p256, BigUint, Cocks, Dsa, EcElGamal, Ecdh, Ecdsa, Ecies, Ed25519, EdwardsDh, EdwardsElGamal,
    ElGamal, MlDsa, MlDsaParameterSet, MlKem, MlKemParameterSet, NtruEes1087Ep2, NtruEes401Ep1,
    NtruEes449Ep1, NtruEes677Ep1, NtruHps509, NtruHps677, NtruHps821, NtruHrss701, Paillier, Rabin,
    Rsa, RsaOaep, RsaPss, SchmidtSamoa, X25519, X448,
};
use cryptography::{Csprng, CtrDrbgAes256, Sha256};

const MSG: [u8; 32] = [0x42; 32];
const EC_MSG: [u8; 16] = [0x24; 16];
const OAEP_LABEL: &[u8] = b"pilot-pk-oaep";
const OAEP_SEED: [u8; 32] = [0x11; 32];
const PSS_SALT: [u8; 32] = [0x22; 32];

fn ms_per_op(elapsed: std::time::Duration, n: usize) -> f64 {
    elapsed.as_secs_f64() * 1000.0 / n as f64
}

fn pk_iters(base: usize) -> usize {
    static SCALE_PERCENT: OnceLock<usize> = OnceLock::new();
    let scale = *SCALE_PERCENT.get_or_init(|| {
        std::env::var("PILOT_PK_ITERS_PERCENT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .map(|v| v.clamp(1, 100))
            .unwrap_or(25)
    });
    base.saturating_mul(scale).div_ceil(100).max(1)
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
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecdsa::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdsa_sign" => {
            let (_, priv_key) = Ecdsa::generate(p256(), &mut rng);
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.sign_message_bytes::<Sha256>(&MSG).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdsa_verify" => {
            let (pub_key, priv_key) = Ecdsa::generate(p256(), &mut rng);
            let sig = priv_key.sign_message_bytes::<Sha256>(&MSG).unwrap();
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.verify_message_bytes::<Sha256>(&MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ECDH (P-256) ──────────────────────────────────────────────────────
        "ecdh_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecdh::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdh_agree" => {
            let (pub_a, _) = Ecdh::generate(p256(), &mut rng);
            let (_, priv_b) = Ecdh::generate(p256(), &mut rng);
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree_x_coordinate(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecdh_serialize" => {
            let (pub_key, _) = Ecdh::generate(p256(), &mut rng);
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.to_wire_bytes());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ECIES (P-256) ─────────────────────────────────────────────────────
        "ecies_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ecies::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecies_encrypt" => {
            let (pub_key, _) = Ecies::generate(p256(), &mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ecies_decrypt" => {
            let (pub_key, priv_key) = Ecies::generate(p256(), &mut rng);
            let ct = pub_key.encrypt(&MSG, &mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── EC ElGamal (P-256) ────────────────────────────────────────────────
        "ec_elgamal_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EcElGamal::generate(p256(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ec_elgamal_encrypt" => {
            let (pub_key, _) = EcElGamal::generate(p256(), &mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&EC_MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ec_elgamal_decrypt" => {
            let (pub_key, priv_key) = EcElGamal::generate(p256(), &mut rng);
            let ct = pub_key.encrypt(&EC_MSG, &mut rng).unwrap();
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Ed25519 ───────────────────────────────────────────────────────────
        "ed25519_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Ed25519::generate(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ed25519_sign" => {
            let (_, priv_key) = Ed25519::generate(&mut rng);
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.sign_message_bytes(&MSG));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ed25519_verify" => {
            let (pub_key, priv_key) = Ed25519::generate(&mut rng);
            let sig = priv_key.sign_message_bytes(&MSG);
            let n = pk_iters(1000);
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
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree_compressed_point(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_dh_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EdwardsDh::generate(ed25519_curve(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_dh_serialize" => {
            let (pub_key, _) = EdwardsDh::generate(ed25519_curve(), &mut rng);
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.to_wire_bytes());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Edwards ElGamal (Ed25519 curve) ───────────────────────────────────
        "edwards_elgamal_keygen" => {
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(EdwardsElGamal::generate(ed25519_curve(), &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_elgamal_encrypt" => {
            let (pub_key, _) = EdwardsElGamal::generate(ed25519_curve(), &mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt_int(7, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "edwards_elgamal_decrypt" => {
            let (pub_key, priv_key) = EdwardsElGamal::generate(ed25519_curve(), &mut rng);
            let ct = pub_key.encrypt_int(7, &mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt_int(&ct, 32).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── DSA (1024-bit) ────────────────────────────────────────────────────
        "dsa_keygen_1024" => {
            let n = pk_iters(10);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Dsa::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "dsa_sign_1024" => {
            let (_, priv_key) = Dsa::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.sign_message_bytes::<Sha256>(&MSG).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "dsa_verify_1024" => {
            let (pub_key, priv_key) = Dsa::generate(&mut rng, 1024).unwrap();
            let sig = priv_key.sign_message_bytes::<Sha256>(&MSG).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.verify_message_bytes::<Sha256>(&MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ElGamal (1024-bit) ────────────────────────────────────────────────
        "elgamal_keygen_1024" => {
            let n = pk_iters(5);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(ElGamal::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "elgamal_encrypt_1024" => {
            let (pub_key, _) = ElGamal::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "elgamal_decrypt_1024" => {
            let (pub_key, priv_key) = ElGamal::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Paillier (1024-bit) ───────────────────────────────────────────────
        "paillier_keygen_1024" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Paillier::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "paillier_encrypt_1024" => {
            let (pub_key, _) = Paillier::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(30);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "paillier_decrypt_1024" => {
            let (pub_key, priv_key) = Paillier::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let n = pk_iters(30);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "paillier_rerandomize_1024" => {
            let (pub_key, _) = Paillier::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let n = pk_iters(50);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.rerandomize(&ct, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "paillier_add_1024" => {
            let (pub_key, priv_key) = Paillier::generate(&mut rng, 1024).unwrap();
            let ct_a = pub_key.encrypt(&MSG, &mut rng).unwrap();
            let ct_b = pub_key.encrypt(&[0x01], &mut rng).unwrap();
            let n = pk_iters(2000);
            let mut combined = pub_key.add_ciphertexts(&ct_a, &ct_b).unwrap();
            let t0 = Instant::now();
            for _ in 0..n {
                combined = black_box(pub_key.add_ciphertexts(&ct_a, &ct_b).unwrap());
            }
            let combined_plaintext = priv_key.decrypt(&combined);
            let expected = BigUint::from_be_bytes(&MSG).add_ref(&BigUint::from_u64(1));
            assert_eq!(combined_plaintext, expected.to_be_bytes());
            ms_per_op(t0.elapsed(), n)
        }
        // ── Cocks (1024-bit) ──────────────────────────────────────────────────
        "cocks_keygen_1024" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Cocks::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "cocks_encrypt_1024" => {
            let (pub_key, _) = Cocks::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(300);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "cocks_decrypt_1024" => {
            let (pub_key, priv_key) = Cocks::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG).unwrap();
            let n = pk_iters(1500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Rabin (1024-bit) ──────────────────────────────────────────────────
        "rabin_keygen_1024" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Rabin::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rabin_encrypt_1024" => {
            let (pub_key, _) = Rabin::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(5000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rabin_decrypt_1024" => {
            let (pub_key, priv_key) = Rabin::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG).unwrap();
            let n = pk_iters(200);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── Schmidt-Samoa (1024-bit) ──────────────────────────────────────────
        "schmidt_samoa_keygen_1024" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(SchmidtSamoa::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "schmidt_samoa_encrypt_1024" => {
            let (pub_key, _) = SchmidtSamoa::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(300);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(pub_key.encrypt(&MSG).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "schmidt_samoa_decrypt_1024" => {
            let (pub_key, priv_key) = SchmidtSamoa::generate(&mut rng, 1024).unwrap();
            let ct = pub_key.encrypt(&MSG).unwrap();
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_key.decrypt(&ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── RSA (1024-bit) ────────────────────────────────────────────────────
        "rsa_keygen_1024" => {
            let n = pk_iters(10);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Rsa::generate(&mut rng, 1024).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_encrypt_1024" => {
            let (pub_key, _) = Rsa::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(
                    RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap(),
                );
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_decrypt_1024" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let ct = RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaOaep::<Sha256>::decrypt(&priv_key, OAEP_LABEL, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_sign_1024" => {
            let (_, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let n = pk_iters(100);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_verify_1024" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 1024).unwrap();
            let sig = RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap();
            let n = pk_iters(1000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::verify(&pub_key, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── RSA (2048-bit) ────────────────────────────────────────────────────
        "rsa_keygen_2048" => {
            let n = pk_iters(3);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(Rsa::generate(&mut rng, 2048).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_encrypt_2048" => {
            let (pub_key, _) = Rsa::generate(&mut rng, 2048).unwrap();
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(
                    RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap(),
                );
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_decrypt_2048" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let ct = RsaOaep::<Sha256>::encrypt(&pub_key, OAEP_LABEL, &MSG, &OAEP_SEED).unwrap();
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaOaep::<Sha256>::decrypt(&priv_key, OAEP_LABEL, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_sign_2048" => {
            let (_, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "rsa_verify_2048" => {
            let (pub_key, priv_key) = Rsa::generate(&mut rng, 2048).unwrap();
            let sig = RsaPss::<Sha256>::sign(&priv_key, &MSG, &PSS_SALT).unwrap();
            let n = pk_iters(200);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(RsaPss::<Sha256>::verify(&pub_key, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ML-KEM (Kyber) ───────────────────────────────────────────────────
        "mlkem512_keygen" => {
            let n = pk_iters(200);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::keygen(MlKemParameterSet::MlKem512, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem512_encaps" => {
            let (pk, _) = MlKem::keygen(MlKemParameterSet::MlKem512, &mut rng).unwrap();
            let n = pk_iters(200);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::encaps(&pk, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem512_decaps" => {
            let (pk, sk) = MlKem::keygen(MlKemParameterSet::MlKem512, &mut rng).unwrap();
            let (ct, _) = MlKem::encaps(&pk, &mut rng).unwrap();
            let n = pk_iters(200);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::decaps(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem768_keygen" => {
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem768_encaps" => {
            let (pk, _) = MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).unwrap();
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::encaps(&pk, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem768_decaps" => {
            let (pk, sk) = MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).unwrap();
            let (ct, _) = MlKem::encaps(&pk, &mut rng).unwrap();
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::decaps(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem1024_keygen" => {
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::keygen(MlKemParameterSet::MlKem1024, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem1024_encaps" => {
            let (pk, _) = MlKem::keygen(MlKemParameterSet::MlKem1024, &mut rng).unwrap();
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::encaps(&pk, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mlkem1024_decaps" => {
            let (pk, sk) = MlKem::keygen(MlKemParameterSet::MlKem1024, &mut rng).unwrap();
            let (ct, _) = MlKem::encaps(&pk, &mut rng).unwrap();
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlKem::decaps(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── ML-DSA (Dilithium) ───────────────────────────────────────────────
        "mldsa44_keygen" => {
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::keygen(MlDsaParameterSet::MlDsa44, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa44_sign" => {
            let (_, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa44, &mut rng).unwrap();
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::sign(&sk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa44_verify" => {
            let (pk, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa44, &mut rng).unwrap();
            let sig = MlDsa::sign(&sk, &MSG, &mut rng).unwrap();
            let n = pk_iters(120);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::verify(&pk, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa65_keygen" => {
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa65_sign" => {
            let (_, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng).unwrap();
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::sign(&sk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa65_verify" => {
            let (pk, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng).unwrap();
            let sig = MlDsa::sign(&sk, &MSG, &mut rng).unwrap();
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::verify(&pk, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa87_keygen" => {
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::keygen(MlDsaParameterSet::MlDsa87, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa87_sign" => {
            let (_, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa87, &mut rng).unwrap();
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::sign(&sk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "mldsa87_verify" => {
            let (pk, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa87, &mut rng).unwrap();
            let sig = MlDsa::sign(&sk, &MSG, &mut rng).unwrap();
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(MlDsa::verify(&pk, &MSG, &sig));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRU-HPS-2048-509 (NIST PQC round 3) ─────────────────────────────
        "ntruhps509_keygen" => {
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps509::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps509_encaps" => {
            let (pk, _) = NtruHps509::keygen(&mut rng);
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps509::encaps(&pk, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps509_decaps" => {
            let (pk, sk) = NtruHps509::keygen(&mut rng);
            let (ct, _) = NtruHps509::encaps(&pk, &mut rng);
            let n = pk_iters(80);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps509::decaps(&sk, &ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRU-HPS-2048-677 (NIST PQC round 3) ─────────────────────────────
        "ntruhps677_keygen" => {
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps677::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps677_encaps" => {
            let (pk, _) = NtruHps677::keygen(&mut rng);
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps677::encaps(&pk, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps677_decaps" => {
            let (pk, sk) = NtruHps677::keygen(&mut rng);
            let (ct, _) = NtruHps677::encaps(&pk, &mut rng);
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps677::decaps(&sk, &ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRU-HPS-4096-821 (NIST PQC round 3) ─────────────────────────────
        "ntruhps821_keygen" => {
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps821::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps821_encaps" => {
            let (pk, _) = NtruHps821::keygen(&mut rng);
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps821::encaps(&pk, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhps821_decaps" => {
            let (pk, sk) = NtruHps821::keygen(&mut rng);
            let (ct, _) = NtruHps821::encaps(&pk, &mut rng);
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHps821::decaps(&sk, &ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRU-HRSS-701 (NIST PQC round 3) ─────────────────────────────────
        "ntruhrss701_keygen" => {
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHrss701::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhrss701_encaps" => {
            let (pk, _) = NtruHrss701::keygen(&mut rng);
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHrss701::encaps(&pk, &mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruhrss701_decaps" => {
            let (pk, sk) = NtruHrss701::keygen(&mut rng);
            let (ct, _) = NtruHrss701::encaps(&pk, &mut rng);
            let n = pk_iters(60);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruHrss701::decaps(&sk, &ct));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRUEncrypt EES401EP1 (IEEE Std 1363.1-2008, SHA-1) ──────────────
        "ntruees401ep1_keygen" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes401Ep1::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees401ep1_encrypt" => {
            let (pk, _) = NtruEes401Ep1::keygen(&mut rng);
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes401Ep1::encrypt(&pk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees401ep1_decrypt" => {
            let (pk, sk) = NtruEes401Ep1::keygen(&mut rng);
            let ct = NtruEes401Ep1::encrypt(&pk, &MSG, &mut rng).unwrap();
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes401Ep1::decrypt(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRUEncrypt EES449EP1 (IEEE Std 1363.1-2008, SHA-1) ──────────────
        "ntruees449ep1_keygen" => {
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes449Ep1::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees449ep1_encrypt" => {
            let (pk, _) = NtruEes449Ep1::keygen(&mut rng);
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes449Ep1::encrypt(&pk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees449ep1_decrypt" => {
            let (pk, sk) = NtruEes449Ep1::keygen(&mut rng);
            let ct = NtruEes449Ep1::encrypt(&pk, &MSG, &mut rng).unwrap();
            let n = pk_iters(40);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes449Ep1::decrypt(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRUEncrypt EES677EP1 (IEEE Std 1363.1-2008, SHA-256) ────────────
        "ntruees677ep1_keygen" => {
            let n = pk_iters(15);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes677Ep1::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees677ep1_encrypt" => {
            let (pk, _) = NtruEes677Ep1::keygen(&mut rng);
            let n = pk_iters(30);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes677Ep1::encrypt(&pk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees677ep1_decrypt" => {
            let (pk, sk) = NtruEes677Ep1::keygen(&mut rng);
            let ct = NtruEes677Ep1::encrypt(&pk, &MSG, &mut rng).unwrap();
            let n = pk_iters(30);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes677Ep1::decrypt(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── NTRUEncrypt EES1087EP2 (IEEE Std 1363.1-2008, SHA-256) ───────────
        "ntruees1087ep2_keygen" => {
            let n = pk_iters(10);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes1087Ep2::keygen(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees1087ep2_encrypt" => {
            let (pk, _) = NtruEes1087Ep2::keygen(&mut rng);
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes1087Ep2::encrypt(&pk, &MSG, &mut rng).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "ntruees1087ep2_decrypt" => {
            let (pk, sk) = NtruEes1087Ep2::keygen(&mut rng);
            let ct = NtruEes1087Ep2::encrypt(&pk, &MSG, &mut rng).unwrap();
            let n = pk_iters(20);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(NtruEes1087Ep2::decrypt(&sk, &ct).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── X25519 (RFC 7748) ─────────────────────────────────────────────────
        "x25519_keygen" => {
            let n = pk_iters(2000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X25519::generate(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x25519_agree" => {
            let (pub_a, _) = X25519::generate(&mut rng);
            let (_, priv_b) = X25519::generate(&mut rng);
            let n = pk_iters(2000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x25519_scalar_mult_base" => {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            let n = pk_iters(2000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X25519::scalar_mult_base(&secret));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x25519_scalar_mult" => {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            let mut u = [0u8; 32];
            u[0] = 9;
            let n = pk_iters(2000);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X25519::scalar_mult(&secret, &u));
            }
            ms_per_op(t0.elapsed(), n)
        }
        // ── X448 (RFC 7748) ───────────────────────────────────────────────────
        "x448_keygen" => {
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X448::generate(&mut rng));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x448_agree" => {
            let (pub_a, _) = X448::generate(&mut rng);
            let (_, priv_b) = X448::generate(&mut rng);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(priv_b.agree(&pub_a).unwrap());
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x448_scalar_mult_base" => {
            let mut secret = [0u8; 56];
            rng.fill_bytes(&mut secret);
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X448::scalar_mult_base(&secret));
            }
            ms_per_op(t0.elapsed(), n)
        }
        "x448_scalar_mult" => {
            let mut secret = [0u8; 56];
            rng.fill_bytes(&mut secret);
            let mut u = [0u8; 56];
            u[0] = 5;
            let n = pk_iters(500);
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(X448::scalar_mult(&secret, &u));
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
