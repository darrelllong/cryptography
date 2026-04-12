//! Fuzz block-cipher modes: GCM, EAX, CBC, CTR, ChaCha20-Poly1305, and
//! AES Key Wrap.
//!
//! For authenticated modes the invariant is:
//!   decrypt(encrypt(pt)) == pt  AND  tag verifies.
//! For unauthenticated modes (CBC, CTR):
//!   decrypt(encrypt(pt)) == pt.
#![no_main]

use cryptography::{Aes128, AesKeyWrap, Cbc, ChaCha20Poly1305, Ctr, Eax, Gcm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let mode = data[0] % 6;
    let rest = &data[1..];

    match mode {
        0 => {
            // GCM-AES-128
            const K: usize = 16;
            const N: usize = 12;
            if rest.len() < K + N {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let nonce: [u8; N] = rest[K..K + N].try_into().unwrap();
            let pt = &rest[K + N..];
            let gcm = Gcm::new(Aes128::new(&key));
            let mut buf = pt.to_vec();
            let tag = gcm.encrypt(&nonce, b"fuzz-aad", &mut buf);
            let ok = gcm.decrypt(&nonce, b"fuzz-aad", &mut buf, &tag);
            assert!(ok, "GCM: decrypt returned false for a valid ciphertext");
            assert_eq!(buf, pt, "GCM: roundtrip mismatch");
        }
        1 => {
            // EAX-AES-128
            const K: usize = 16;
            const N: usize = 12;
            if rest.len() < K + N {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let nonce: [u8; N] = rest[K..K + N].try_into().unwrap();
            let pt = &rest[K + N..];
            let eax = Eax::new(Aes128::new(&key));
            let mut buf = pt.to_vec();
            let tag = eax.encrypt(&nonce, b"fuzz-aad", &mut buf);
            let ok = eax.decrypt(&nonce, b"fuzz-aad", &mut buf, &tag);
            assert!(ok, "EAX: decrypt returned false for a valid ciphertext");
            assert_eq!(buf, pt, "EAX: roundtrip mismatch");
        }
        2 => {
            // CBC-AES-128 (no padding; input must be block-aligned)
            const K: usize = 16;
            const B: usize = 16;
            if rest.len() < K + B {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let iv = &rest[K..K + B];
            let raw = &rest[K + B..];
            let aligned = (raw.len() / B) * B;
            if aligned == 0 {
                return;
            }
            let mut buf = raw[..aligned].to_vec();
            let orig = buf.clone();
            let cbc = Cbc::new(Aes128::new(&key));
            cbc.encrypt_nopad(iv, &mut buf);
            cbc.decrypt_nopad(iv, &mut buf);
            assert_eq!(buf, orig, "CBC: roundtrip mismatch");
        }
        3 => {
            // CTR-AES-128 (double application == identity)
            const K: usize = 16;
            const N: usize = 16;
            if rest.len() < K + N {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let counter = &rest[K..K + N];
            let pt = &rest[K + N..];
            let mut buf = pt.to_vec();
            let ctr = Ctr::new(Aes128::new(&key));
            ctr.apply_keystream(counter, &mut buf);
            ctr.apply_keystream(counter, &mut buf);
            assert_eq!(buf, pt, "CTR: double keystream application != identity");
        }
        4 => {
            // ChaCha20-Poly1305
            const K: usize = 32;
            const N: usize = 12;
            if rest.len() < K + N {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let nonce: [u8; N] = rest[K..K + N].try_into().unwrap();
            let pt = &rest[K + N..];
            let aead = ChaCha20Poly1305::new(&key);
            let (ct, tag) = aead.encrypt(&nonce, b"fuzz-aad", pt);
            let recovered = aead
                .decrypt(&nonce, b"fuzz-aad", &ct, &tag)
                .expect("ChaCha20-Poly1305: decrypt returned None for a valid ciphertext");
            assert_eq!(recovered, pt, "ChaCha20-Poly1305: roundtrip mismatch");
        }
        _ => {
            // AES Key Wrap (RFC 3394): data must be a multiple of 8 bytes
            const K: usize = 16;
            if rest.len() < K + 8 {
                return;
            }
            let key: [u8; K] = rest[..K].try_into().unwrap();
            let raw = &rest[K..];
            let aligned = (raw.len() / 8) * 8;
            if aligned == 0 {
                return;
            }
            let kew = AesKeyWrap::new(Aes128::new(&key));
            if let Some(wrapped) = kew.wrap_key(&raw[..aligned]) {
                let unwrapped = kew
                    .unwrap_key(&wrapped)
                    .expect("AES KeyWrap: unwrap returned None for a valid wrapped key");
                assert_eq!(
                    unwrapped,
                    &raw[..aligned],
                    "AES KeyWrap: roundtrip mismatch",
                );
            }
        }
    }
});
