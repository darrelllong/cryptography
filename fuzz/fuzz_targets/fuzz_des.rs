//! DES and Triple-DES under fuzzer-chosen keys: the T-table and constant-time
//! implementations accept the same keys, agree block for block, and each
//! round-trips. A key both refuse (bad parity, weak or semi-weak) ends the
//! input; the refusal rules themselves are unit-tested in `ciphers/des.rs`.
//!
//! Layout: `[option][key][8-byte block]` with an 8-, 24- or 16-byte key for
//! single DES, keying option 1 and keying option 2.
#![no_main]

use cryptography::{BlockCipher, Des, DesCt, TripleDes, TripleDesCt};
use libfuzzer_sys::fuzz_target;

const BLK: usize = 8;

fn agree<A: BlockCipher, B: BlockCipher>(name: &str, a: &A, b: &B, pt: [u8; BLK]) {
    let mut from_a = pt;
    a.encrypt(&mut from_a);
    let mut from_b = pt;
    b.encrypt(&mut from_b);
    assert_eq!(
        from_a, from_b,
        "{name}: the two implementations encrypt differently"
    );
    a.decrypt(&mut from_a);
    b.decrypt(&mut from_b);
    assert_eq!(from_a, pt, "{name}: round trip");
    assert_eq!(from_b, pt, "{name}: round trip (constant time)");
}

fuzz_target!(|data: &[u8]| {
    let Some((&option, rest)) = data.split_first() else {
        return;
    };
    match option % 3 {
        0 => {
            if rest.len() < 8 + BLK {
                return;
            }
            let key: [u8; 8] = rest[..8].try_into().expect("8 bytes");
            let pt: [u8; BLK] = rest[8..8 + BLK].try_into().expect("8 bytes");
            let (a, b) = (Des::new(&key), DesCt::new(&key));
            assert_eq!(
                a.is_ok(),
                b.is_ok(),
                "DES: the implementations disagree on the key"
            );
            if let (Ok(a), Ok(b)) = (a, b) {
                agree("DES", &a, &b, pt);
            }
        }
        1 => {
            if rest.len() < 24 + BLK {
                return;
            }
            let key: [u8; 24] = rest[..24].try_into().expect("24 bytes");
            let pt: [u8; BLK] = rest[24..24 + BLK].try_into().expect("8 bytes");
            let (a, b) = (TripleDes::new_3key(&key), TripleDesCt::new_3key(&key));
            assert_eq!(
                a.is_ok(),
                b.is_ok(),
                "TDEA option 1: the implementations disagree on the key"
            );
            if let (Ok(a), Ok(b)) = (a, b) {
                agree("TDEA option 1", &a, &b, pt);
            }
        }
        _ => {
            if rest.len() < 16 + BLK {
                return;
            }
            let key: [u8; 16] = rest[..16].try_into().expect("16 bytes");
            let pt: [u8; BLK] = rest[16..16 + BLK].try_into().expect("8 bytes");
            let (a, b) = (TripleDes::new_2key(&key), TripleDesCt::new_2key(&key));
            assert_eq!(
                a.is_ok(),
                b.is_ok(),
                "TDEA option 2: the implementations disagree on the key"
            );
            if let (Ok(a), Ok(b)) = (a, b) {
                agree("TDEA option 2", &a, &b, pt);
            }
        }
    }
});
