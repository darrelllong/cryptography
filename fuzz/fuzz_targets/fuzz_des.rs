//! Fuzz DES and Triple-DES: roundtrip across all keying options.
//!
//! DES keys have odd-parity bits; `new()` enforces parity while `new_unchecked()`
//! skips it.  We fuzz both paths: if parity is bad the checked constructor just
//! returns Err and we skip that variant, otherwise we run roundtrips for both
//! checked and unchecked instances (they must agree).
#![no_main]

use cryptography::{BlockCipher, Des, DesCt, TripleDes};
use libfuzzer_sys::fuzz_target;

const BLK: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 4 {
        // Single DES (8-byte key).
        0 => {
            const KEY: usize = 8;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            // Always test unchecked path.
            let c = Des::new_unchecked(&key);
            let mut blk = pt;
            c.encrypt(&mut blk);
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "Des (unchecked) roundtrip failed");

            // Also test the Ct variant on the same key.
            let cct = DesCt::new_unchecked(&key);
            let mut blk2 = pt;
            cct.encrypt(&mut blk2);
            let mut blk3 = pt;
            c.encrypt(&mut blk3);
            assert_eq!(blk2, blk3, "Des vs DesCt encrypt differ");
            cct.decrypt(&mut blk2);
            assert_eq!(blk2, pt, "DesCt roundtrip failed");

            // If parity is valid, checked constructor must also agree.
            if let Ok(cv) = Des::new(&key) {
                let mut blk4 = pt;
                cv.encrypt(&mut blk4);
                assert_eq!(blk4, blk3, "Des::new vs new_unchecked encrypt differ");
            }
        }

        // TDES keying option 1: three independent keys (24-byte key).
        1 => {
            const KEY: usize = 24;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            if let Ok(c) = TripleDes::new_3key(&key) {
                let mut blk = pt;
                c.encrypt(&mut blk);
                c.decrypt(&mut blk);
                assert_eq!(blk, pt, "TripleDes 3-key roundtrip failed");
            }
        }

        // TDES keying option 2: K1=K3 (16-byte key).
        2 => {
            const KEY: usize = 16;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            if let Ok(c) = TripleDes::new_2key(&key) {
                let mut blk = pt;
                c.encrypt(&mut blk);
                c.decrypt(&mut blk);
                assert_eq!(blk, pt, "TripleDes 2-key roundtrip failed");
            }
        }

        // TDES single-key: K1=K2=K3 (degenerates to DES, 8-byte key).
        _ => {
            const KEY: usize = 8;
            if data.len() < 1 + KEY + BLK {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let pt: [u8; BLK] = data[1 + KEY..1 + KEY + BLK].try_into().unwrap();

            let c = TripleDes::new_single_key_unchecked(&key);
            let mut blk = pt;
            c.encrypt(&mut blk);
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "TripleDes single-key roundtrip failed");
        }
    }
});
