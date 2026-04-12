//! Fuzz Magma (GOST R 34.12-2015 / RFC 8891):
//! roundtrip and regular-vs-Ct consistency.
//! 256-bit key, 64-bit block.
#![no_main]

use cryptography::{BlockCipher, Magma, MagmaCt};
use libfuzzer_sys::fuzz_target;

const KEY: usize = 32;
const BLK: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + BLK {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let pt: [u8; BLK] = data[KEY..KEY + BLK].try_into().unwrap();

    let c = Magma::new(&key);
    let cct = MagmaCt::new(&key);

    let mut blk = pt;
    c.encrypt(&mut blk);
    let ct = blk;
    c.decrypt(&mut blk);
    assert_eq!(blk, pt, "Magma roundtrip failed");

    let mut blk2 = pt;
    cct.encrypt(&mut blk2);
    assert_eq!(blk2, ct, "Magma vs MagmaCt encrypt differ");
    cct.decrypt(&mut blk2);
    assert_eq!(blk2, pt, "MagmaCt roundtrip failed");
});
