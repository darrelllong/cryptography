//! Fuzz Salsa20: XOR involution.
//! 32-byte key, 8-byte nonce.
#![no_main]

use cryptography::Salsa20;
use libfuzzer_sys::fuzz_target;

const KEY: usize = 32;
const NONCE: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + NONCE {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let nonce: [u8; NONCE] = data[KEY..KEY + NONCE].try_into().unwrap();
    let plaintext = &data[KEY + NONCE..];

    let mut buf = plaintext.to_vec();

    let mut enc = Salsa20::new(&key, &nonce);
    enc.apply_keystream(&mut buf);

    let mut dec = Salsa20::new(&key, &nonce);
    dec.apply_keystream(&mut buf);

    assert_eq!(buf, plaintext, "Salsa20 XOR involution failed");
});
