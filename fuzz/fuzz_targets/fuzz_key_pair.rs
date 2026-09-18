//! Key-pair consistency: what each scheme does when a private key meets a
//! public key that is not its own.
//!
//! Layout: `[selector][48-byte seed][48-byte seed][message]`. Two key pairs
//! come from the two seeds, and the scheme the selector names is asked to
//! cross them. Failing closed is the property: a signature must not verify
//! under a foreign key, an agreement must not land on the same secret, and a
//! decapsulation under the wrong key must reach implicit rejection rather
//! than the encapsulated secret.
//!
//! ML-KEM also has an import to exercise. FIPS 203 §7.1 step 4 requires a
//! decapsulation key to be checked against the encapsulation key inside it,
//! so a key spliced from one pair's secret and another's public part — with
//! the §7.2 modulus check, the §7.3 hash check and canonical packing all
//! intact — must be refused by that test and nothing else.
#![no_main]

use cryptography::public_key::ec::p256;
use cryptography::public_key::ecdsa::Ecdsa;
use cryptography::public_key::ed25519::Ed25519;
use cryptography::public_key::ml_dsa::{MlDsa, MlDsaParameterSet};
use cryptography::public_key::ml_kem::{MlKem, MlKemParameterSet, MlKemPrivateKey};
use cryptography::public_key::x25519::X25519;
use cryptography::{CtrDrbgAes256, Sha256};
use libfuzzer_sys::fuzz_target;

/// The DRBG seed length, which is what each key pair is drawn from.
const SEED_LEN: usize = 48;

/// ML-KEM-512's decapsulation key is `dk_PKE || ek || H(ek) || z`, and
/// `|dk_PKE| = 384k` while the whole is `768k + 96` bytes, so the secret part
/// a splice replaces is this long.
fn dk_pke_len(params: MlKemParameterSet) -> usize {
    384 * params.k()
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if rest.len() < 2 * SEED_LEN {
        return;
    }
    let (seed_a, rest) = rest.split_at(SEED_LEN);
    let (seed_b, message) = rest.split_at(SEED_LEN);
    if seed_a == seed_b {
        // The same seed gives the same key pair, and crossing a pair with
        // itself proves nothing.
        return;
    }
    // Ed25519 takes a 32-byte seed, the rest a 48-byte DRBG seed, so two
    // seeds that differ only past byte 32 are the same key pair to it.
    if seed_a[..32] == seed_b[..32] {
        return;
    }
    let mut rng_a = CtrDrbgAes256::new(seed_a.try_into().expect("48 bytes"));
    let mut rng_b = CtrDrbgAes256::new(seed_b.try_into().expect("48 bytes"));

    match selector % 5 {
        0 => {
            let seed_a: [u8; 32] = seed_a[..32].try_into().expect("32 bytes");
            let seed_b: [u8; 32] = seed_b[..32].try_into().expect("32 bytes");
            let (public_a, private_a) = Ed25519::from_seed(seed_a);
            let (public_b, _) = Ed25519::from_seed(seed_b);
            let signature = private_a.sign_message(message);
            assert!(
                public_a.verify_message(message, &signature),
                "Ed25519: a signature failed under its own key"
            );
            assert!(
                !public_b.verify_message(message, &signature),
                "Ed25519: a signature verified under a foreign key"
            );
        }
        1 => {
            let (public_a, private_a) = Ecdsa::generate(p256(), &mut rng_a);
            let (public_b, _) = Ecdsa::generate(p256(), &mut rng_b);
            let Some(signature) = private_a.sign_message::<Sha256>(message) else {
                return;
            };
            assert!(
                public_a.verify_message::<Sha256>(message, &signature),
                "ECDSA: a signature failed under its own key"
            );
            assert!(
                !public_b.verify_message::<Sha256>(message, &signature),
                "ECDSA: a signature verified under a foreign key"
            );
        }
        2 => {
            let (public_a, private_a) = X25519::generate(&mut rng_a);
            let (public_b, private_b) = X25519::generate(&mut rng_b);
            let (Some(shared_a), Some(shared_b)) =
                (private_a.agree(&public_b), private_b.agree(&public_a))
            else {
                return;
            };
            assert_eq!(shared_a, shared_b, "X25519: the two sides disagreed");
            // The pair itself must be consistent: the public key a generation
            // hands back is the one the private key derives.
            assert_eq!(
                private_a.to_public_key().to_raw_bytes(),
                public_a.to_raw_bytes(),
                "X25519: the generated pair is inconsistent"
            );
            assert_eq!(
                private_b.to_public_key().to_raw_bytes(),
                public_b.to_raw_bytes(),
                "X25519: the generated pair is inconsistent"
            );
        }
        3 => {
            let params = MlKemParameterSet::MlKem512;
            let (Some((public_a, private_a)), Some((_, private_b))) = (
                MlKem::keygen(params, &mut rng_a),
                MlKem::keygen(params, &mut rng_b),
            ) else {
                panic!("ML-KEM key generation failed its own consistency test");
            };
            let (ciphertext, secret) = MlKem::encaps(&public_a, &mut rng_a);
            let recovered = MlKem::decaps(&private_a, &ciphertext).expect("the matching key");
            assert_eq!(
                recovered.to_wire_bytes(),
                secret.to_wire_bytes(),
                "ML-KEM: the right key did not recover the secret"
            );
            let rejected = MlKem::decaps(&private_b, &ciphertext).expect("the same parameter set");
            assert_ne!(
                rejected.to_wire_bytes(),
                secret.to_wire_bytes(),
                "ML-KEM: a foreign key recovered the secret"
            );

            // The §7.1 step 4 splice: one pair's secret polynomial vector
            // under another pair's public part. Everything the other checks
            // look at is untouched, so only the pair-wise test can refuse it.
            let mut spliced = private_b.to_wire_bytes();
            let secret_part = dk_pke_len(params);
            spliced[..secret_part].copy_from_slice(&private_a.to_wire_bytes()[..secret_part]);
            assert!(
                MlKemPrivateKey::from_wire_bytes(params, &spliced, &mut rng_a).is_none(),
                "ML-KEM: a spliced decapsulation key was imported"
            );
            // The same import of an unspliced key must succeed, or the
            // refusal above says nothing.
            assert!(
                MlKemPrivateKey::from_wire_bytes(params, &private_b.to_wire_bytes(), &mut rng_a)
                    .is_some(),
                "ML-KEM: a well-formed decapsulation key was refused"
            );
        }
        _ => {
            let params = MlDsaParameterSet::MlDsa44;
            let (public_a, private_a) = MlDsa::keygen(params, &mut rng_a);
            let (public_b, _) = MlDsa::keygen(params, &mut rng_b);
            let Some(signature) = MlDsa::sign(&private_a, message, &mut rng_a) else {
                return;
            };
            assert!(
                MlDsa::verify(&public_a, message, &signature),
                "ML-DSA: a signature failed under its own key"
            );
            assert!(
                !MlDsa::verify(&public_b, message, &signature),
                "ML-DSA: a signature verified under a foreign key"
            );
        }
    }
});
