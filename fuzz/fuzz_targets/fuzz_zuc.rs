//! Fuzz ZUC-128: XOR involution and regular-vs-Ct consistency.
//! 16-byte key, 16-byte IV.
#![no_main]

use cryptography::{StreamCipher, Zuc128, Zuc128Ct};
use libfuzzer_sys::fuzz_target;

const KEY: usize = 16;
const IV: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + IV {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let iv: [u8; IV] = data[KEY..KEY + IV].try_into().unwrap();
    let plaintext = &data[KEY + IV..];

    // Zuc128 involution.
    let mut buf = plaintext.to_vec();
    let mut enc = Zuc128::new(&key, &iv);
    enc.apply_keystream(&mut buf);
    let mut dec = Zuc128::new(&key, &iv);
    dec.apply_keystream(&mut buf);
    assert_eq!(buf, plaintext, "Zuc128 XOR involution failed");

    // Zuc128Ct involution.
    let mut buf2 = plaintext.to_vec();
    let mut enc2 = Zuc128Ct::new(&key, &iv);
    enc2.apply_keystream(&mut buf2);
    let mut dec2 = Zuc128Ct::new(&key, &iv);
    dec2.apply_keystream(&mut buf2);
    assert_eq!(buf2, plaintext, "Zuc128Ct XOR involution failed");

    // Consistency: both variants must produce the same keystream.
    let mut ks1 = vec![0u8; plaintext.len()];
    Zuc128::new(&key, &iv).fill(&mut ks1);

    let mut ks2 = vec![0u8; plaintext.len()];
    Zuc128Ct::new(&key, &iv).fill(&mut ks2);

    assert_eq!(ks1, ks2, "Zuc128 vs Zuc128Ct keystream differ");
});
