//! Fuzz Serpent-128/192/256: encrypt/decrypt round trips through the
//! `BlockCipher` trait (128-bit block for all key sizes). The `*Ct` names are
//! aliases of the same types, so there is no second path to compare against.
#![no_main]

use cryptography::{BlockCipher, Serpent128, Serpent192, Serpent256};
use libfuzzer_sys::fuzz_target;

macro_rules! roundtrip {
    ($data:expr, $key_len:expr, $blk_len:expr, $C:ty) => {{
        const K: usize = $key_len;
        const B: usize = $blk_len;
        if $data.len() >= K + B {
            let key: [u8; K] = $data[..K].try_into().unwrap();
            let pt: [u8; B] = $data[K..K + B].try_into().unwrap();

            let c = <$C>::new(&key);

            let mut blk = pt;
            c.encrypt(&mut blk);
            let ct = blk;
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "{} roundtrip failed", stringify!($C));
            assert_eq!(
                c.encrypt_block(&pt),
                ct,
                "{} trait/inherent mismatch",
                stringify!($C)
            );
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 3 {
        0 => roundtrip!(&data[1..], 16, 16, Serpent128),
        1 => roundtrip!(&data[1..], 24, 16, Serpent192),
        _ => roundtrip!(&data[1..], 32, 16, Serpent256),
    }
});
