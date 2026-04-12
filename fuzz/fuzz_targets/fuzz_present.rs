//! Fuzz PRESENT-80 and PRESENT-128: roundtrip and regular-vs-Ct consistency.
//! 64-bit block for both variants.
#![no_main]

use cryptography::{BlockCipher, Present128, Present128Ct, Present80, Present80Ct};
use libfuzzer_sys::fuzz_target;

const BLK: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 2 {
        // PRESENT-80: 10-byte key.
        0 => {
            const KEY: usize = 10;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            let c = Present80::new(&key);
            let cct = Present80Ct::new(&key);

            let mut blk = pt;
            c.encrypt(&mut blk);
            let ct = blk;
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "Present80 roundtrip failed");

            let mut blk2 = pt;
            cct.encrypt(&mut blk2);
            assert_eq!(blk2, ct, "Present80 vs Present80Ct encrypt differ");
            cct.decrypt(&mut blk2);
            assert_eq!(blk2, pt, "Present80Ct roundtrip failed");
        }

        // PRESENT-128: 16-byte key.
        _ => {
            const KEY: usize = 16;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            let c = Present128::new(&key);
            let cct = Present128Ct::new(&key);

            let mut blk = pt;
            c.encrypt(&mut blk);
            let ct = blk;
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "Present128 roundtrip failed");

            let mut blk2 = pt;
            cct.encrypt(&mut blk2);
            assert_eq!(blk2, ct, "Present128 vs Present128Ct encrypt differ");
            cct.decrypt(&mut blk2);
            assert_eq!(blk2, pt, "Present128Ct roundtrip failed");
        }
    }
});
