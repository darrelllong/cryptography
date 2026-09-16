//! This crate wipes secrets in every build: its own scrubbing, and rump's
//! `BigUint` limb wiping, which it enables. Wiping must never change a
//! cryptographic result.
use cryptography::{zeroize_slice, Aes256Ct, Csprng, CtrDrbgAes256};

#[test]
fn slice_scrubbing_is_always_active() {
    let mut bytes = [0xa5u8; 37];
    let mut words = [0x1234_5678u32; 5];
    zeroize_slice(&mut bytes);
    zeroize_slice(&mut words);
    assert_eq!(bytes, [0; 37]);
    assert_eq!(words, [0; 5]);
}

#[test]
fn caller_key_erasure_preserves_cipher_output() {
    let mut key = [0x42; 32];
    let reference = Aes256Ct::new(&key);
    let cipher = Aes256Ct::new_wiping(&mut key);
    assert_eq!(key, [0; 32]);
    assert_eq!(
        cipher.encrypt_block(&[0x27; 16]),
        reference.encrypt_block(&[0x27; 16])
    );
}

#[test]
fn seed_erasure_preserves_drbg_output() {
    let mut seed = [0x42; 48];
    let mut reference = CtrDrbgAes256::new(&seed);
    let mut rng = CtrDrbgAes256::new_wiping(&mut seed);
    assert_eq!(seed, [0; 48]);
    let mut expected = [0; 64];
    let mut actual = [0; 64];
    reference.fill_bytes(&mut expected);
    rng.fill_bytes(&mut actual);
    assert_eq!(actual, expected);
}
