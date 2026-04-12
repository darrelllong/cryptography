//! Fuzz ChaCha20 and XChaCha20:
//! - XOR involution: encrypt then decrypt gives back plaintext.
//! - fill() consistency: fill(plaintext) == apply_keystream(plaintext).
#![no_main]

use cryptography::{ChaCha20, XChaCha20};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 2 {
        // ChaCha20: 32-byte key, 12-byte nonce.
        0 => {
            const KEY: usize = 32;
            const NONCE: usize = 12;
            if data.len() < 1 + KEY + NONCE {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let nonce: [u8; NONCE] = data[1 + KEY..1 + KEY + NONCE].try_into().unwrap();
            let plaintext = &data[1 + KEY + NONCE..];

            // Encrypt with apply_keystream; save ciphertext.
            let mut buf = plaintext.to_vec();
            ChaCha20::new(&key, &nonce).apply_keystream(&mut buf);
            let ciphertext = buf.clone();

            // Roundtrip: decrypt must recover the plaintext.
            ChaCha20::new(&key, &nonce).apply_keystream(&mut buf);
            assert_eq!(buf, plaintext, "ChaCha20 XOR involution failed");

            // fill() must produce the same output as apply_keystream().
            let mut buf2 = plaintext.to_vec();
            ChaCha20::new(&key, &nonce).fill(&mut buf2);
            assert_eq!(buf2, ciphertext, "ChaCha20 fill vs apply_keystream differ");
        }

        // XChaCha20: 32-byte key, 24-byte nonce.
        _ => {
            const KEY: usize = 32;
            const NONCE: usize = 24;
            if data.len() < 1 + KEY + NONCE {
                return;
            }
            let key: [u8; KEY] = data[1..1 + KEY].try_into().unwrap();
            let nonce: [u8; NONCE] = data[1 + KEY..1 + KEY + NONCE].try_into().unwrap();
            let plaintext = &data[1 + KEY + NONCE..];

            let mut buf = plaintext.to_vec();
            XChaCha20::new(&key, &nonce).apply_keystream(&mut buf);
            let ciphertext = buf.clone();

            XChaCha20::new(&key, &nonce).apply_keystream(&mut buf);
            assert_eq!(buf, plaintext, "XChaCha20 XOR involution failed");

            let mut buf2 = plaintext.to_vec();
            XChaCha20::new(&key, &nonce).fill(&mut buf2);
            assert_eq!(buf2, ciphertext, "XChaCha20 fill vs apply_keystream differ");
        }
    }
});
