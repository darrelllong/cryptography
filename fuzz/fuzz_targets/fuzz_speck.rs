//! Fuzz all 10 Speck variants: roundtrip (decrypt(encrypt(pt)) == pt).
//! Speck is ARX-based with no table-lookup variant.
#![no_main]

use cryptography::{
    BlockCipher, Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96,
    Speck64_128, Speck64_96, Speck96_144, Speck96_96,
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
    match data[0] % 10 {
        0 => roundtrip!(&data[1..],  8,  4, Speck32_64),    // Speck 32/64
        1 => roundtrip!(&data[1..],  9,  6, Speck48_72),    // Speck 48/72
        2 => roundtrip!(&data[1..], 12,  6, Speck48_96),    // Speck 48/96
        3 => roundtrip!(&data[1..], 12,  8, Speck64_96),    // Speck 64/96
        4 => roundtrip!(&data[1..], 16,  8, Speck64_128),   // Speck 64/128
        5 => roundtrip!(&data[1..], 12, 12, Speck96_96),    // Speck 96/96
        6 => roundtrip!(&data[1..], 18, 12, Speck96_144),   // Speck 96/144
        7 => roundtrip!(&data[1..], 16, 16, Speck128_128),  // Speck 128/128
        8 => roundtrip!(&data[1..], 24, 16, Speck128_192),  // Speck 128/192
        _ => roundtrip!(&data[1..], 32, 16, Speck128_256),  // Speck 128/256
    }
});
