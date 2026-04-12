//! Fuzz Grasshopper (GOST R 34.12-2015 / RFC 7801):
//! roundtrip and regular-vs-Ct consistency.
//! 256-bit key, 128-bit block.
#![no_main]

use cryptography::{BlockCipher, Grasshopper, GrasshopperCt};
use libfuzzer_sys::fuzz_target;

const KEY: usize = 32;
const BLK: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY + BLK {
        return;
    }
    let key: [u8; KEY] = data[..KEY].try_into().unwrap();
    let pt: [u8; BLK] = data[KEY..KEY + BLK].try_into().unwrap();

    let c = Grasshopper::new(&key);
    let cct = GrasshopperCt::new(&key);

    let mut blk = pt;
    c.encrypt(&mut blk);
    let ct = blk;
    c.decrypt(&mut blk);
    assert_eq!(blk, pt, "Grasshopper roundtrip failed");

    let mut blk2 = pt;
    cct.encrypt(&mut blk2);
    assert_eq!(blk2, ct, "Grasshopper vs GrasshopperCt encrypt differ");
    cct.decrypt(&mut blk2);
    assert_eq!(blk2, pt, "GrasshopperCt roundtrip failed");
});
