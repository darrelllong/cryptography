//! Fuzz Serpent-128/192/256: roundtrip and regular-vs-Ct consistency.
//! 128-bit block for all key sizes.
#![no_main]

use cryptography::{
    BlockCipher, Serpent128, Serpent128Ct, Serpent192, Serpent192Ct, Serpent256, Serpent256Ct,
};
use libfuzzer_sys::fuzz_target;

macro_rules! roundtrip_pair {
    ($data:expr, $key_len:expr, $blk_len:expr, $C:ty, $CCt:ty) => {{
        const K: usize = $key_len;
        const B: usize = $blk_len;
        if $data.len() >= K + B {
            let key: [u8; K] = $data[..K].try_into().unwrap();
            let pt: [u8; B] = $data[K..K + B].try_into().unwrap();

            let c = <$C>::new(&key);
            let cct = <$CCt>::new(&key);

            let mut blk = pt;
            c.encrypt(&mut blk);
            let ct = blk;
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "{} roundtrip failed", stringify!($C));

            let mut blk2 = pt;
            cct.encrypt(&mut blk2);
            assert_eq!(
                blk2,
                ct,
                "{} vs {} encrypt differ",
                stringify!($C),
                stringify!($CCt)
            );
            cct.decrypt(&mut blk2);
            assert_eq!(blk2, pt, "{} roundtrip failed", stringify!($CCt));
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 3 {
        0 => roundtrip_pair!(&data[1..], 16, 16, Serpent128, Serpent128Ct),
        1 => roundtrip_pair!(&data[1..], 24, 16, Serpent192, Serpent192Ct),
        _ => roundtrip_pair!(&data[1..], 32, 16, Serpent256, Serpent256Ct),
    }
});
