//! Fuzz CAST-128 (Cast5): roundtrip and regular-vs-Ct consistency.
//! CAST-128 has a fixed 16-byte (128-bit) key and 8-byte block.
#![no_main]

use cryptography::{BlockCipher, Cast128, Cast128Ct};
use libfuzzer_sys::fuzz_target;

const KEY: usize = 16;
const BLK: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + BLK {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let pt: [u8; BLK] = data[KEY..KEY + BLK].try_into().unwrap();

    let c = Cast128::new(&key);
    let cct = Cast128Ct::new(&key);

    let mut blk = pt;
    c.encrypt(&mut blk);
    let ct = blk;
    c.decrypt(&mut blk);
    assert_eq!(blk, pt, "Cast128 roundtrip failed");

    let mut blk2 = pt;
    cct.encrypt(&mut blk2);
    assert_eq!(blk2, ct, "Cast128 vs Cast128Ct encrypt differ");
    cct.decrypt(&mut blk2);
    assert_eq!(blk2, pt, "Cast128Ct roundtrip failed");
});
