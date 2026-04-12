//! Fuzz Rabbit: XOR involution.
//! 16-byte key, 8-byte IV.
#![no_main]

use cryptography::Rabbit;
use libfuzzer_sys::fuzz_target;

const KEY: usize = 16;
const IV: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + IV {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let iv: [u8; IV] = data[KEY..KEY + IV].try_into().unwrap();
    let plaintext = &data[KEY + IV..];

    let mut buf = plaintext.to_vec();

    let mut enc = Rabbit::new(&key, &iv);
    enc.apply_keystream(&mut buf);

    let mut dec = Rabbit::new(&key, &iv);
    dec.apply_keystream(&mut buf);

    assert_eq!(buf, plaintext, "Rabbit XOR involution failed");
});
