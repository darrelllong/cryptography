//! Fuzz AES-128/192/256: roundtrip (decrypt(encrypt(pt)) == pt) and
//! consistency between the table-based and constant-time variants.
#![no_main]

use cryptography::{Aes128, Aes128Ct, Aes192, Aes192Ct, Aes256, Aes256Ct, BlockCipher};
use libfuzzer_sys::fuzz_target;

/// Test that a block-cipher pair (regular + Ct) produce the same ciphertext
/// and that decrypt is the exact inverse of encrypt for both.
macro_rules! roundtrip_pair {
    ($data:expr, $key_len:expr, $blk_len:expr, $C:ty, $CCt:ty) => {{
        const K: usize = $key_len;
        const B: usize = $blk_len;
        if $data.len() >= K + B {
            let key: [u8; K] = $data[..K].try_into().unwrap();
            let pt: [u8; B] = $data[K..K + B].try_into().unwrap();

            let c = <$C>::new(&key);
            let cct = <$CCt>::new(&key);

            // Regular roundtrip.
            let mut blk = pt;
            c.encrypt(&mut blk);
            let ct = blk;
            c.decrypt(&mut blk);
            assert_eq!(blk, pt, "{} roundtrip failed", stringify!($C));

            // Ct roundtrip and consistency with regular output.
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
        0 => roundtrip_pair!(&data[1..], 16, 16, Aes128, Aes128Ct),
        1 => roundtrip_pair!(&data[1..], 24, 16, Aes192, Aes192Ct),
        _ => roundtrip_pair!(&data[1..], 32, 16, Aes256, Aes256Ct),
    }
});
