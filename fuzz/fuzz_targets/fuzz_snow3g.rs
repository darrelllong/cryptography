//! Fuzz SNOW 3G: XOR involution and regular-vs-Ct consistency.
//! 16-byte key, 16-byte IV.
#![no_main]

use cryptography::{Snow3g, Snow3gCt, StreamCipher};
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

    // Snow3g involution.
    let mut buf = plaintext.to_vec();
    let mut enc = Snow3g::new(&key, &iv);
    enc.apply_keystream(&mut buf);
    let mut dec = Snow3g::new(&key, &iv);
    dec.apply_keystream(&mut buf);
    assert_eq!(buf, plaintext, "Snow3g XOR involution failed");

    // Snow3gCt involution.
    let mut buf2 = plaintext.to_vec();
    let mut enc2 = Snow3gCt::new(&key, &iv);
    enc2.apply_keystream(&mut buf2);
    let mut dec2 = Snow3gCt::new(&key, &iv);
    dec2.apply_keystream(&mut buf2);
    assert_eq!(buf2, plaintext, "Snow3gCt XOR involution failed");

    // Consistency: both variants must produce the same keystream.
    let mut ks1 = vec![0u8; plaintext.len()];
    Snow3g::new(&key, &iv).fill(&mut ks1);

    let mut ks2 = vec![0u8; plaintext.len()];
    Snow3gCt::new(&key, &iv).fill(&mut ks2);

    assert_eq!(ks1, ks2, "Snow3g vs Snow3gCt keystream differ");
});
