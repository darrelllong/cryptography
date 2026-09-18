//! Seed corpora for the fuzz targets whose inputs have a structure mutation
//! does not find: a valid key blob or a DER container. Run
//! `cargo run --manifest-path fuzz/Cargo.toml --bin seed_corpus` from the
//! repository root; it writes under `fuzz/seeds/<target>/`, which is kept in
//! the repository. A run names the seeds as a second, read-only corpus, so
//! the inputs libFuzzer adds go to the ignored `fuzz/corpus/`:
//! `cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target>`.
//! `fuzz/regressions/<target>/` holds minimized inputs at boundaries a target
//! must keep handling; name it as a further read-only corpus, or replay it
//! with `fuzz/target/<triple>/release/<target> fuzz/regressions/<target>/*`.
//! `fuzz/campaigns/` records each long campaign's build, hosts and per-target
//! executions and coverage.
//!
//! Every key comes from a fixed-seed DRBG, so the corpora are reproducible.

use std::fs;
use std::path::{Path, PathBuf};

use cryptography::public_key::{
    dh::Dh,
    dsa::Dsa,
    ec::p256,
    ecdh::Ecdh,
    ecdsa::Ecdsa,
    ecies::Ecies,
    ed25519::Ed25519,
    ml_dsa::{MlDsa, MlDsaParameterSet},
    ml_kem::{MlKem, MlKemParameterSet},
    rsa::Rsa,
    x25519::X25519,
    x448::X448,
};
use cryptography::{CtrDrbgAes256, Sha256};

fn seeds() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds")
}

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = seeds().join(target);
    fs::create_dir_all(&dir).expect("create corpus directory");
    fs::write(dir.join(name), bytes).expect("write seed");
    println!("{target}/{name}: {} bytes", bytes.len());
}

fn with_selector(selector: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![selector];
    out.extend_from_slice(payload);
    out
}

/// `fuzz_pk_parse` reads its selector as a little-endian `u16`.
fn with_selector16(selector: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = selector.to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn length_prefixed(blob: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(blob.len())
        .expect("blob under 64 KiB")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(blob);
    out.extend_from_slice(rest);
    out
}


/// `fuzz_hpke` reads each field as a length byte followed by that many bytes.
/// The first byte selects the AEAD and the mode: `selector % 3` the AEAD,
/// `(selector / 3) % 4` the mode.
fn hpke_input(selector: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![selector];
    for field in fields {
        out.push(u8::try_from(field.len()).expect("a field under 256 bytes"));
        out.extend_from_slice(field);
    }
    out
}


/// `fuzz_explicit_curve` reads `[selector][u16 len][value]`. A selector whose
/// `which` field is 7 replaces nothing, so the named curve the low bits pick
/// must pass its own validation; those are the seeds that reach the deep
/// checks, which random bytes do not.
fn explicit_curve_input(selector: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![selector];
    out.extend_from_slice(
        &u16::try_from(value.len())
            .expect("a value under 64 KiB")
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    out
}


/// `fuzz_key_pair` reads `[selector][48-byte seed][48-byte seed][message]`.
/// The two seeds must differ in their first 32 bytes, which is all Ed25519
/// takes of them.
fn key_pair_input(selector: u8, message: &[u8]) -> Vec<u8> {
    let mut out = vec![selector];
    out.extend_from_slice(&[0x5au8; 48]);
    out.extend_from_slice(&[0xa5u8; 48]);
    out.extend_from_slice(message);
    out
}

fn main() {
    let mut rng = CtrDrbgAes256::new(&[0x42u8; 48]);

    // Finite-field groups: toy sizes keep the seeds small and the fuzzer fast.
    let dsa_params = Dsa::generate_toy_params(&mut rng, 512).expect("toy DSA group");
    let (dsa_pk, dsa_sk) = Dsa::generate(&dsa_params, &mut rng);
    let (_, dsa_sk2) = Dsa::generate(&dsa_params, &mut rng);
    let dh_params = Dh::generate_toy_params(&mut rng, 512).expect("toy DH group");
    let (dh_pk, dh_sk) = Dh::generate(&dh_params, &mut rng);
    let (_, dh_sk2) = Dh::generate(&dh_params, &mut rng);

    // fuzz_dsa: [u16 len][blob][32-byte nonce][32-byte digest].
    let mut tail = vec![0x11u8; 32];
    tail.extend_from_slice(&[0x22u8; 32]);
    write(
        "fuzz_dsa",
        "toy",
        &length_prefixed(&dsa_sk.to_key_blob(), &tail),
    );
    // fuzz_dh: [u16 len][blob][blob].
    write(
        "fuzz_dh",
        "toy_pair",
        &length_prefixed(&dh_sk.to_key_blob(), &dh_sk2.to_key_blob()),
    );
    let _ = dsa_sk2;

    // fuzz_ecies: [48-byte seed][at][bit][u16 len][blob][plaintext].
    let (_, ecies_sk) = Ecies::generate(p256(), &mut rng);
    let mut ecies = vec![0x33u8; 48];
    ecies.extend_from_slice(&[7, 3]);
    ecies.extend_from_slice(&length_prefixed(&ecies_sk.to_key_blob(), b"seed plaintext"));
    write("fuzz_ecies", "p256", &ecies);

    // fuzz_pkix_parse: [arm][DER].
    let (rsa_pk, rsa_sk) = Rsa::generate(&mut rng, 1024).expect("RSA-1024");
    write(
        "fuzz_pkix_parse",
        "00_rsa_spki",
        &with_selector(0, &rsa_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "01_rsa_pkcs8",
        &with_selector(1, &rsa_sk.to_pkcs8_der()),
    );
    let (ecdsa_pk, ecdsa_sk) = Ecdsa::generate(p256(), &mut rng);
    write(
        "fuzz_pkix_parse",
        "02_ecdsa_spki",
        &with_selector(2, &ecdsa_pk.to_spki_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "03_ecdsa_sec1",
        &with_selector(3, &ecdsa_sk.to_sec1_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "04_ecdsa_pkcs8",
        &with_selector(4, &ecdsa_sk.to_pkcs8_der().expect("named curve")),
    );
    let (ecdh_pk, ecdh_sk) = Ecdh::generate(p256(), &mut rng);
    write(
        "fuzz_pkix_parse",
        "05_ecdh_spki",
        &with_selector(5, &ecdh_pk.to_spki_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "06_ecdh_sec1",
        &with_selector(6, &ecdh_sk.to_sec1_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "07_ecdh_pkcs8",
        &with_selector(7, &ecdh_sk.to_pkcs8_der().expect("named curve")),
    );
    let ecies_pk = ecies_sk.to_public_key();
    write(
        "fuzz_pkix_parse",
        "08_ecies_spki",
        &with_selector(8, &ecies_pk.to_spki_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "09_ecies_sec1",
        &with_selector(9, &ecies_sk.to_sec1_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "10_ecies_pkcs8",
        &with_selector(10, &ecies_sk.to_pkcs8_der().expect("named curve")),
    );
    write(
        "fuzz_pkix_parse",
        "11_dh_spki",
        &with_selector(11, &dh_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "12_dh_pkcs8",
        &with_selector(12, &dh_sk.to_pkcs8_der()),
    );
    write(
        "fuzz_pkix_parse",
        "13_dsa_spki",
        &with_selector(13, &dsa_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "14_dsa_pkcs8",
        &with_selector(14, &dsa_sk.to_pkcs8_der()),
    );
    write(
        "fuzz_pkix_parse",
        "15_dh_params",
        &with_selector(15, &dh_params.to_der()),
    );
    write(
        "fuzz_pkix_parse",
        "16_dsa_params",
        &with_selector(16, &dsa_params.to_der()),
    );
    let dsa_sig = dsa_sk
        .sign_message::<Sha256>(b"seed")
        .expect("DSA signature");
    write(
        "fuzz_pkix_parse",
        "17_dsa_sig",
        &with_selector(17, &dsa_sig.to_der()),
    );
    let ecdsa_sig = ecdsa_sk
        .sign_message::<Sha256>(b"seed")
        .expect("ECDSA signature");
    write(
        "fuzz_pkix_parse",
        "18_ecdsa_sig",
        &with_selector(18, &ecdsa_sig.to_der()),
    );
    let (ed_pk, ed_sk) = Ed25519::from_seed([0x44u8; 32]);
    write(
        "fuzz_pkix_parse",
        "19_ed25519_spki",
        &with_selector(19, &ed_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "20_ed25519_pkcs8",
        &with_selector(20, &ed_sk.to_pkcs8_der()),
    );
    let (x_pk, x_sk) = X25519::generate(&mut rng);
    write(
        "fuzz_pkix_parse",
        "21_x25519_spki",
        &with_selector(21, &x_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "22_x25519_pkcs8",
        &with_selector(22, &x_sk.to_pkcs8_der()),
    );
    let (x448_pk, x448_sk) = X448::generate(&mut rng);
    write(
        "fuzz_pkix_parse",
        "23_x448_spki",
        &with_selector(23, &x448_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "24_x448_pkcs8",
        &with_selector(24, &x448_sk.to_pkcs8_der()),
    );
    let (kem_pk, kem_sk) = MlKem::keygen_from_seed(MlKemParameterSet::MlKem512, &[0x55u8; 64]);
    write(
        "fuzz_pkix_parse",
        "25_mlkem_spki",
        &with_selector(25, &kem_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "26_mlkem_pkcs8",
        &with_selector(26, &kem_sk.to_pkcs8_der()),
    );
    let (mldsa_pk, mldsa_sk) = MlDsa::keygen_from_seed(MlDsaParameterSet::MlDsa44, &[0x66u8; 32]);
    write(
        "fuzz_pkix_parse",
        "27_mldsa_spki",
        &with_selector(27, &mldsa_pk.to_spki_der()),
    );
    write(
        "fuzz_pkix_parse",
        "28_mldsa_pkcs8",
        &with_selector(28, &mldsa_sk.to_pkcs8_der()),
    );

    // fuzz_pk_parse: [u16 selector][payload], selector taken modulo 48.
    write(
        "fuzz_pk_parse",
        "00_mlkem512_pk_wire",
        &with_selector16(0, &kem_pk.to_wire_bytes()),
    );
    write(
        "fuzz_pk_parse",
        "09_mlkem_pk_blob",
        &with_selector16(9, &kem_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "10_mlkem_sk_blob",
        &with_selector16(10, &kem_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "20_mldsa_pk_blob",
        &with_selector16(20, &mldsa_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "21_mldsa_sk_blob",
        &with_selector16(21, &mldsa_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "22_ecdsa_p256_wire",
        &with_selector16(22, &ecdsa_pk.to_wire_bytes()),
    );
    write(
        "fuzz_pk_parse",
        "38_ecdsa_pk_blob",
        &with_selector16(38, &ecdsa_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "39_ecdsa_sk_blob",
        &with_selector16(39, &ecdsa_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "40_ecdh_pk_blob",
        &with_selector16(40, &ecdh_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "41_ecdh_sk_blob",
        &with_selector16(41, &ecdh_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "42_dsa_pk_blob",
        &with_selector16(42, &dsa_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "43_dsa_sk_blob",
        &with_selector16(43, &dsa_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "44_dh_pk_blob",
        &with_selector16(44, &dh_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "45_dh_sk_blob",
        &with_selector16(45, &dh_sk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "46_ed25519_pk_blob",
        &with_selector16(46, &ed_pk.to_key_blob()),
    );
    write(
        "fuzz_pk_parse",
        "47_ed25519_sk_blob",
        &with_selector16(47, &ed_sk.to_key_blob()),
    );

    // fuzz_hpke: the mode's fields must all be present before a setup succeeds,
    // which mutation reaches for the base mode and not for the PSK ones.
    let hpke_fields: [&[u8]; 8] = [
        b"recipient seed",
        b"sender seed",
        b"pre-shared key",
        b"pre-shared key identifier",
        b"info string",
        b"associated data",
        b"the sealed message",
        b"",
    ];
    write("fuzz_hpke", "aes128gcm_base", &hpke_input(0, &hpke_fields));
    write("fuzz_hpke", "chacha20poly1305_psk", &hpke_input(5, &hpke_fields));
    write("fuzz_hpke", "aes256gcm_auth", &hpke_input(7, &hpke_fields));
    write("fuzz_hpke", "aes128gcm_authpsk", &hpke_input(9, &hpke_fields));

    // fuzz_explicit_curve: one selector byte carries both fields the target
    // reads — `(selector >> 3) % 8` picks which parameter is replaced, and
    // `selector % 6` picks the curve — so each seed's byte is the value that
    // satisfies both. A `which` of 7 replaces nothing, which is the case that
    // requires a named curve to pass its own validation.
    for (name, selector) in [
        ("p256", 56u8),
        ("p384", 57),
        ("p521", 58),
        ("secp256k1", 59),
        ("p192", 60),
        ("p224", 61),
    ] {
        write(
            "fuzz_explicit_curve",
            &format!("named_{name}"),
            &explicit_curve_input(selector, &[]),
        );
    }
    // The same, one per replaceable field of P-256, so a mutation starts from
    // a curve that is valid up to the field it changes.
    for (field, selector) in [
        ("p", 2u8),
        ("a", 14),
        ("b", 20),
        ("n", 26),
        ("gx", 32),
        ("gy", 44),
        ("h", 50),
    ] {
        write(
            "fuzz_explicit_curve",
            &format!("p256_{field}"),
            &explicit_curve_input(selector, &[0x01]),
        );
    }

    // fuzz_key_pair: one seed per scheme the selector reaches, since a key
    // pair is only crossed after two full DRBG seeds are present.
    for (scheme, selector) in [
        ("ed25519", 0u8),
        ("ecdsa_p256", 1),
        ("x25519", 2),
        ("ml_kem_512", 3),
        ("ml_dsa_44", 4),
    ] {
        write(
            "fuzz_key_pair",
            scheme,
            &key_pair_input(selector, b"a message to sign"),
        );
    }
}
