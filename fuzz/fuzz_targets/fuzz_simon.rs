//! Fuzz all 10 Simon variants: roundtrip (decrypt(encrypt(pt)) == pt).
//! Simon is ARX-based with no table-lookup variant, so no Ct consistency check.
#![no_main]

use cryptography::{
    BlockCipher, Simon128_128, Simon128_192, Simon128_256, Simon32_64, Simon48_72, Simon48_96,
    Simon64_128, Simon64_96, Simon96_144, Simon96_96,
};
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
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "{} roundtrip failed", stringify!($C));
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Dispatch across all 10 variants.  Key sizes and block sizes from the paper.
    match data[0] % 10 {
        0 => roundtrip!(&data[1..],  8,  4, Simon32_64),    // Simon 32/64
        1 => roundtrip!(&data[1..],  9,  6, Simon48_72),    // Simon 48/72
        2 => roundtrip!(&data[1..], 12,  6, Simon48_96),    // Simon 48/96
        3 => roundtrip!(&data[1..], 12,  8, Simon64_96),    // Simon 64/96
        4 => roundtrip!(&data[1..], 16,  8, Simon64_128),   // Simon 64/128
        5 => roundtrip!(&data[1..], 12, 12, Simon96_96),    // Simon 96/96
        6 => roundtrip!(&data[1..], 18, 12, Simon96_144),   // Simon 96/144
        7 => roundtrip!(&data[1..], 16, 16, Simon128_128),  // Simon 128/128
        8 => roundtrip!(&data[1..], 24, 16, Simon128_192),  // Simon 128/192
        _ => roundtrip!(&data[1..], 32, 16, Simon128_256),  // Simon 128/256
    }
});
