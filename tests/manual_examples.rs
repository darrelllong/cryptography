use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cryptography::public_key::ec_edwards::ed25519;
use cryptography::vt::{
    p256, BigUint, Dh, Dsa, Ecdh, Ecdsa, Ecies, Ed25519, EdDsa, EdwardsDh, ElGamal, MlDsa,
    MlDsaParameterSet, MlDsaSignature, MlKem, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey,
    NtruHps509, NtruHps509Ciphertext, NtruHps509PublicKey, NtruHrss701, NtruHrss701PublicKey,
    Paillier, Rsa, RsaOaep, RsaPss,
};
use cryptography::{
    Aes128, Aes256, Cbc, ChaCha20, Cmac, Csprng, Ctr, CtrDrbgAes256, Gcm, Gmac, Hmac, Rabbit,
    Sha256, Sha512, Shake256, Snow3g, Xof,
};

fn temp_path(name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cryptography-manual-{}-{}-{}",
        std::process::id(),
        unique,
        name
    ))
}

fn encrypt_file(input: &Path, output: &Path, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) {
    let gcm = Gcm::new(Aes256::new(key));
    let mut data = fs::read(input).expect("read plaintext");
    let tag = gcm.encrypt(nonce, aad, &mut data);

    let mut out = Vec::with_capacity(tag.len() + data.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&data);
    fs::write(output, out).expect("write ciphertext");
}

fn decrypt_file(input: &Path, output: &Path, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) {
    let gcm = Gcm::new(Aes256::new(key));
    let mut enc = fs::read(input).expect("read ciphertext");
    let ciphertext = enc.split_off(16);
    let tag = enc;
    let mut data = ciphertext;
    assert!(gcm.decrypt(nonce, aad, &mut data, &tag));
    fs::write(output, data).expect("write plaintext");
}

fn encrypt_file_ctr(input: &Path, output: &Path, key: &[u8; 32], counter: &[u8; 16]) {
    let ctr = Ctr::new(Aes256::new(key));
    let mut data = fs::read(input).expect("read plaintext");
    ctr.apply_keystream(counter, &mut data);
    fs::write(output, data).expect("write ciphertext");
}

fn decrypt_file_ctr(input: &Path, output: &Path, key: &[u8; 32], counter: &[u8; 16]) {
    let ctr = Ctr::new(Aes256::new(key));
    let mut data = fs::read(input).expect("read ciphertext");
    ctr.apply_keystream(counter, &mut data);
    fs::write(output, data).expect("write plaintext");
}

#[test]
fn manual_csprng_hash_xof_and_mac_examples() {
    let mut seed = [0x42u8; 48];
    let mut rng = CtrDrbgAes256::new_wiping(&mut seed);
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    assert!(bytes.iter().any(|&b| b != 0));

    let digest = Sha256::digest(b"hello");
    assert_eq!(digest.len(), 32);

    let mut shake = Shake256::new();
    shake.update(b"context");
    shake.update(b"message");
    let mut xof_out = [0u8; 64];
    shake.squeeze(&mut xof_out);
    assert!(xof_out.iter().any(|&b| b != 0));

    let hmac_tag = Hmac::<Sha256>::compute(b"secret", b"message");
    assert!(Hmac::<Sha256>::verify(b"secret", b"message", &hmac_tag));

    let cmac = Cmac::new(Aes128::new(&[0u8; 16]));
    let cmac_tag = cmac.compute(b"cmac data");
    assert!(cmac.verify(b"cmac data", &cmac_tag));

    let gmac = Gmac::new(Aes256::new(&[1u8; 32]));
    let gmac_tag = gmac.compute(&[2u8; 12], b"associated-data");
    assert!(gmac.verify(&[2u8; 12], b"associated-data", &gmac_tag));
}

#[test]
fn manual_symmetric_examples() {
    let block_cipher = Aes256::new(&[0u8; 32]);
    let block = block_cipher.encrypt_block(&[0u8; 16]);
    assert_eq!(block_cipher.decrypt_block(&block), [0u8; 16]);

    let cbc = Cbc::new(Aes128::new(&[7u8; 16]));
    let iv = [0u8; 16];
    let mut blocks = *b"0123456789abcdef0123456789abcdef";
    cbc.encrypt_nopad(&iv, &mut blocks);
    cbc.decrypt_nopad(&iv, &mut blocks);
    assert_eq!(&blocks, b"0123456789abcdef0123456789abcdef");

    let ctr = Ctr::new(Aes128::new(&[9u8; 16]));
    let mut ctr_buf = b"ctr mode payload".to_vec();
    let original = ctr_buf.clone();
    ctr.apply_keystream(&[0u8; 16], &mut ctr_buf);
    ctr.apply_keystream(&[0u8; 16], &mut ctr_buf);
    assert_eq!(ctr_buf, original);

    let plaintext_path = temp_path("plain.bin");
    let ciphertext_path = temp_path("cipher.bin");
    let roundtrip_path = temp_path("roundtrip.bin");
    fs::write(&plaintext_path, b"file encryption example").expect("write input");

    encrypt_file(
        &plaintext_path,
        &ciphertext_path,
        &[3u8; 32],
        &[4u8; 12],
        b"file-example",
    );
    decrypt_file(
        &ciphertext_path,
        &roundtrip_path,
        &[3u8; 32],
        &[4u8; 12],
        b"file-example",
    );

    let roundtrip = fs::read(&roundtrip_path).expect("read roundtrip");
    assert_eq!(roundtrip, b"file encryption example");

    let _ = fs::remove_file(&plaintext_path);
    let _ = fs::remove_file(&ciphertext_path);
    let _ = fs::remove_file(&roundtrip_path);
}

#[test]
fn manual_ctr_file_roundtrip_example() {
    let plaintext_path = temp_path("ctr-plain.bin");
    let ciphertext_path = temp_path("ctr-cipher.bin");
    let roundtrip_path = temp_path("ctr-roundtrip.bin");

    fs::write(&plaintext_path, b"counter mode file example").expect("write input");

    encrypt_file_ctr(
        &plaintext_path,
        &ciphertext_path,
        &[0x11u8; 32],
        &[0x22u8; 16],
    );
    decrypt_file_ctr(
        &ciphertext_path,
        &roundtrip_path,
        &[0x11u8; 32],
        &[0x22u8; 16],
    );

    let roundtrip = fs::read(&roundtrip_path).expect("read roundtrip");
    assert_eq!(roundtrip, b"counter mode file example");

    let _ = fs::remove_file(&plaintext_path);
    let _ = fs::remove_file(&ciphertext_path);
    let _ = fs::remove_file(&roundtrip_path);
}

#[test]
fn manual_stream_cipher_examples() {
    let mut chacha = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
    let mut buf = b"stream data".to_vec();
    let original = buf.clone();
    chacha.apply_keystream(&mut buf);
    let mut chacha = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
    chacha.apply_keystream(&mut buf);
    assert_eq!(buf, original);

    let mut rabbit = Rabbit::new(&[1u8; 16], &[2u8; 8]);
    let mut rabbit_stream = [0u8; 32];
    rabbit.fill(&mut rabbit_stream);
    assert!(rabbit_stream.iter().any(|&b| b != 0));

    let mut snow = Snow3g::new(&[3u8; 16], &[4u8; 16]);
    let mut snow_stream = [0u8; 32];
    snow.fill(&mut snow_stream);
    assert!(snow_stream.iter().any(|&b| b != 0));
}

#[test]
fn manual_rsa_examples() {
    let mut rng = CtrDrbgAes256::new(&[7u8; 48]);
    let (public, private) = Rsa::generate(&mut rng, 1024).expect("rsa");

    let ciphertext =
        RsaOaep::<Sha256>::encrypt_rng(&public, b"label", b"hello rsa", &mut rng).expect("oaep");
    let plaintext = RsaOaep::<Sha256>::decrypt(&private, b"label", &ciphertext).expect("decrypt");
    assert_eq!(plaintext, b"hello rsa");

    let signature = RsaPss::<Sha256>::sign_rng(&private, b"hello rsa", &mut rng).expect("pss");
    assert!(RsaPss::<Sha256>::verify(&public, b"hello rsa", &signature));

    let public_spki = public.to_spki_der();
    let private_pkcs8 = private.to_pkcs8_der();
    let public_round = cryptography::vt::RsaPublicKey::from_spki_der(&public_spki).expect("spki");
    let private_round =
        cryptography::vt::RsaPrivateKey::from_pkcs8_der(&private_pkcs8).expect("pkcs8");
    assert_eq!(public_round, public);
    assert_eq!(private_round, private);
}

#[test]
fn manual_finite_field_examples() {
    let mut rng = CtrDrbgAes256::new(&[8u8; 48]);

    let params = Dh::generate_params(&mut rng, 256).expect("dh params");
    let (dh_pub_a, dh_priv_a) = Dh::generate(&params, &mut rng);
    let (dh_pub_b, dh_priv_b) = Dh::generate(&params, &mut rng);
    let dh_shared_a = dh_priv_a.agree_element(&dh_pub_b).expect("dh a");
    let dh_shared_b = dh_priv_b.agree_element(&dh_pub_a).expect("dh b");
    assert_eq!(dh_shared_a, dh_shared_b);

    let (dsa_public, dsa_private) = Dsa::generate(&mut rng, 512).expect("dsa");
    let dsa_sig = dsa_private
        .sign_message::<Sha256>(b"dsa message")
        .expect("dsa sign");
    assert!(dsa_public.verify_message::<Sha256>(b"dsa message", &dsa_sig));
    let dsa_blob = dsa_sig.to_key_blob();
    assert!(dsa_public.verify_message_bytes::<Sha256>(b"dsa message", &dsa_blob));

    let (elg_public, elg_private) = ElGamal::generate(&mut rng, 256).expect("elgamal");
    let elg_cipher = elg_public
        .encrypt(b"elgamal", &mut rng)
        .expect("elgamal encrypt");
    let elg_plain = elg_private.decrypt(&elg_cipher);
    assert_eq!(elg_plain, b"elgamal");
    let elg_ct_blob = elg_cipher.to_key_blob();
    assert_eq!(
        elg_private
            .decrypt_bytes(&elg_ct_blob)
            .expect("elgamal blob decrypt"),
        b"elgamal"
    );

    let (paillier_public, paillier_private) = Paillier::generate(&mut rng, 128).expect("paillier");
    let left = paillier_public
        .encrypt_with_nonce(&BigUint::from_u64(10), &BigUint::from_u64(3))
        .expect("left");
    let right = paillier_public
        .encrypt_with_nonce(&BigUint::from_u64(20), &BigUint::from_u64(5))
        .expect("right");
    let sum_ct = paillier_public.add_ciphertexts(&left, &right).expect("sum");
    assert_eq!(paillier_private.decrypt_raw(&sum_ct), BigUint::from_u64(30));
}

#[test]
fn manual_ec_examples() {
    let mut rng = CtrDrbgAes256::new(&[9u8; 48]);

    let (ecdh_pub_a, ecdh_priv_a) = Ecdh::generate(p256(), &mut rng);
    let (ecdh_pub_b, ecdh_priv_b) = Ecdh::generate(p256(), &mut rng);
    let ecdh_shared_a = ecdh_priv_a.agree_x_coordinate(&ecdh_pub_b).expect("ecdh a");
    let ecdh_shared_b = ecdh_priv_b.agree_x_coordinate(&ecdh_pub_a).expect("ecdh b");
    assert_eq!(ecdh_shared_a, ecdh_shared_b);

    let ecdh_wire = ecdh_pub_a.to_wire_bytes();
    let ecdh_round =
        cryptography::vt::EcdhPublicKey::from_wire_bytes(p256(), &ecdh_wire).expect("ecdh wire");
    assert_eq!(ecdh_round.public_point(), ecdh_pub_a.public_point());

    let (ecdsa_public, ecdsa_private) = Ecdsa::generate(p256(), &mut rng);
    let ecdsa_sig = ecdsa_private
        .sign_message::<Sha256>(b"ecdsa message")
        .expect("ecdsa sign");
    assert!(ecdsa_public.verify_message::<Sha256>(b"ecdsa message", &ecdsa_sig));

    let (ecies_public, ecies_private) = Ecies::generate(p256(), &mut rng);
    let ecies_ct = ecies_public.encrypt(b"ecies payload", &mut rng);
    let ecies_pt = ecies_private.decrypt(&ecies_ct).expect("ecies decrypt");
    assert_eq!(ecies_pt, b"ecies payload");
}

#[test]
fn manual_edwards_examples() {
    let mut rng = CtrDrbgAes256::new(&[10u8; 48]);

    let (ed25519_public, ed25519_private) = Ed25519::generate(&mut rng);
    let ed25519_sig = ed25519_private.sign_message(b"ed25519 message");
    assert!(ed25519_public.verify_message(b"ed25519 message", &ed25519_sig));
    let public_raw = ed25519_public.to_raw_bytes();
    let private_raw = ed25519_private.to_raw_bytes();
    assert!(cryptography::vt::Ed25519PublicKey::from_raw_bytes(&public_raw).is_some());
    assert!(cryptography::vt::Ed25519PrivateKey::from_raw_bytes(&private_raw).is_some());

    let (eddsa_public, eddsa_private) = EdDsa::generate(ed25519(), &mut rng);
    let eddsa_sig = eddsa_private
        .sign_message::<Sha512, _>(b"eddsa message", &mut rng)
        .expect("eddsa sign");
    assert!(eddsa_public.verify_message::<Sha512>(b"eddsa message", &eddsa_sig));
    let eddsa_wire = eddsa_public.to_wire_bytes();
    let eddsa_round =
        cryptography::vt::EdDsaPublicKey::from_wire_bytes(ed25519(), &eddsa_wire).expect("wire");
    assert_eq!(eddsa_round.public_point(), eddsa_public.public_point());

    let (eddh_pub_a, eddh_priv_a) = EdwardsDh::generate(ed25519(), &mut rng);
    let (eddh_pub_b, eddh_priv_b) = EdwardsDh::generate(ed25519(), &mut rng);
    let eddh_shared_a = eddh_priv_a
        .agree_compressed_point(&eddh_pub_b)
        .expect("eddh a");
    let eddh_shared_b = eddh_priv_b
        .agree_compressed_point(&eddh_pub_a)
        .expect("eddh b");
    assert_eq!(eddh_shared_a, eddh_shared_b);
}

#[test]
fn manual_postquantum_examples() {
    let mut rng = CtrDrbgAes256::new(&[11u8; 48]);

    let (kem_pk, kem_sk) = MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).expect("ml-kem");
    let (kem_ct, kem_ss_sender) = MlKem::encaps(&kem_pk, &mut rng).expect("encaps");
    let kem_ss_receiver = MlKem::decaps(&kem_sk, &kem_ct).expect("decaps");
    assert_eq!(
        kem_ss_sender.to_wire_bytes(),
        kem_ss_receiver.to_wire_bytes()
    );

    let kem_pk_wire = kem_pk.to_wire_bytes();
    let kem_pk_round =
        MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem768, &kem_pk_wire).expect("pk");
    assert_eq!(kem_pk_round, kem_pk);

    let kem_sk_blob = kem_sk.to_key_blob();
    let kem_sk_round = MlKemPrivateKey::from_key_blob(&kem_sk_blob).expect("sk");
    assert_eq!(kem_sk_round, kem_sk);

    let fixed_randomness = [0xA5u8; 32];
    let (_, ss1) = MlKem::encaps_with_randomness(&kem_pk_round, &fixed_randomness).expect("ss1");
    let (_, ss2) = MlKem::encaps_with_randomness(&kem_pk_round, &fixed_randomness).expect("ss2");
    assert_eq!(ss1.to_wire_bytes(), ss2.to_wire_bytes());

    let (dsa_pk, dsa_sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng).expect("ml-dsa");
    let sig = MlDsa::sign(&dsa_sk, b"release manifest", &mut rng).expect("sign");
    assert!(MlDsa::verify(&dsa_pk, b"release manifest", &sig));
    assert!(!MlDsa::verify(&dsa_pk, b"tampered", &sig));

    let ctx = b"bundle:v1";
    let fixed_rnd = [0x5Cu8; 32];
    let sig_ctx = MlDsa::sign_with_randomness_and_context(&dsa_sk, b"payload", &fixed_rnd, ctx)
        .expect("sign with context");
    assert!(MlDsa::verify_with_context(
        &dsa_pk, b"payload", &sig_ctx, ctx
    ));
    assert!(!MlDsa::verify_with_context(
        &dsa_pk,
        b"payload",
        &sig_ctx,
        b"bundle:v2"
    ));

    let sig_wire = sig.to_wire_bytes();
    let sig_round =
        MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa65, &sig_wire).expect("signature");
    assert!(MlDsa::verify(&dsa_pk, b"release manifest", &sig_round));

    // NTRU-HPS-2048-509 (NIST PQC round-3 alternate KEM, KAT-validated).
    let (ntru_pk, ntru_sk) = NtruHps509::keygen(&mut rng);
    let (ntru_ct, ntru_ss_sender) = NtruHps509::encaps(&ntru_pk, &mut rng);
    let ntru_ss_receiver = NtruHps509::decaps(&ntru_sk, &ntru_ct);
    assert_eq!(ntru_ss_sender.as_bytes(), ntru_ss_receiver.as_bytes());

    let ntru_pk_wire = ntru_pk.to_wire_bytes();
    let ntru_ct_wire = ntru_ct.to_wire_bytes();
    let ntru_pk_round = NtruHps509PublicKey::from_wire_bytes(&ntru_pk_wire).expect("ntru pk");
    let ntru_ct_round = NtruHps509Ciphertext::from_wire_bytes(&ntru_ct_wire).expect("ntru ct");
    assert_eq!(ntru_pk_round, ntru_pk);
    assert_eq!(ntru_ct_round, ntru_ct);

    // NTRU-HRSS-701 (sister parameter set in the same submission family).
    let (hrss_pk, hrss_sk) = NtruHrss701::keygen(&mut rng);
    let (hrss_ct, hrss_ss_sender) = NtruHrss701::encaps(&hrss_pk, &mut rng);
    let hrss_ss_receiver = NtruHrss701::decaps(&hrss_sk, &hrss_ct);
    assert_eq!(hrss_ss_sender.as_bytes(), hrss_ss_receiver.as_bytes());
    let hrss_pk_round =
        NtruHrss701PublicKey::from_wire_bytes(&hrss_pk.to_wire_bytes()).expect("hrss pk");
    assert_eq!(hrss_pk_round, hrss_pk);
}
