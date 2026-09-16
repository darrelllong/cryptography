//! Message authentication codes: HMAC-SHA-256, CMAC-AES-128, CMAC-AES-256,
//! GMAC-AES-128 (both GHASH back ends) and Poly1305.
//!
//! Layout: `[mac][flip position][flip bit][32-byte key][nonce length byte]
//! [nonce][message]`. Every MAC must accept its own tag, refuse the tag with
//! one flipped bit, refuse the message with one flipped bit under the honest
//! tag, and, where the API streams, give the same tag for the message fed in
//! chunks of a fuzzer-chosen size as for the message fed whole. Poly1305 is
//! keyed with a digest of the key bytes, since its message binding is a
//! probability over uniform keys, not a property of every key.
#![no_main]

use cryptography::{Aes128, Aes256, Cmac, Gmac, GmacVt, Hmac, Poly1305, Sha256};
use libfuzzer_sys::fuzz_target;

const MACS: u8 = 6;

fn flip(buf: &mut [u8], at: usize, bit: u8) -> bool {
    if buf.is_empty() {
        return false;
    }
    let index = at % buf.len();
    buf[index] ^= 1 << (bit % 8);
    true
}

/// `verify` must accept `tag` for `message` and refuse one flipped bit in
/// either.
fn tag_binds(
    name: &str,
    message: &[u8],
    tag: &[u8],
    at: usize,
    bit: u8,
    verify: impl Fn(&[u8], &[u8]) -> bool,
) {
    assert!(verify(message, tag), "{name}: refused its own tag");
    let mut bad_tag = tag.to_vec();
    flip(&mut bad_tag, at, bit);
    assert!(
        !verify(message, &bad_tag),
        "{name}: accepted a tag with one flipped bit"
    );
    let mut bad_message = message.to_vec();
    if flip(&mut bad_message, at, bit) {
        assert!(
            !verify(&bad_message, tag),
            "{name}: accepted a message with one flipped bit"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 + 32 + 1 {
        return;
    }
    let mac = data[0] % MACS;
    let at = usize::from(data[1]);
    let bit = data[2];
    let key: [u8; 32] = data[3..35].try_into().expect("32 bytes");
    let key16: [u8; 16] = key[..16].try_into().expect("16 bytes");
    let nonce_len = 1 + usize::from(data[35] % 16);
    let rest = &data[36..];
    if rest.len() < nonce_len {
        return;
    }
    let (nonce, message) = rest.split_at(nonce_len);
    let step = 1 + usize::from(bit) % 64;

    match mac {
        0 => {
            let whole = Hmac::<Sha256>::compute(&key, message);
            let mut streaming = Hmac::<Sha256>::new(&key);
            for chunk in message.chunks(step) {
                streaming.update(chunk);
            }
            assert_eq!(
                streaming.finalize(),
                whole,
                "HMAC-SHA-256: streaming differs from one-shot"
            );
            tag_binds("HMAC-SHA-256", message, &whole, at, bit, |m, t| {
                Hmac::<Sha256>::verify(&key, m, t)
            });
        }
        1 => {
            let cmac = Cmac::new(Aes128::new(&key16));
            let tag = cmac.compute(message);
            tag_binds("CMAC-AES-128", message, tag.as_ref(), at, bit, |m, t| {
                cmac.verify(m, t)
            });
        }
        2 => {
            let cmac = Cmac::new(Aes256::new(&key));
            let tag = cmac.compute(message);
            tag_binds("CMAC-AES-256", message, tag.as_ref(), at, bit, |m, t| {
                cmac.verify(m, t)
            });
        }
        3 => {
            let gmac = Gmac::new(Aes128::new(&key16));
            let tag = gmac.compute(nonce, message);
            tag_binds("GMAC-AES-128", message, &tag, at, bit, |m, t| {
                gmac.verify(nonce, m, t)
            });
            let mut bad_nonce = nonce.to_vec();
            flip(&mut bad_nonce, at, bit);
            assert!(
                !gmac.verify(&bad_nonce, message, &tag),
                "GMAC-AES-128: accepted a nonce with one flipped bit"
            );
        }
        4 => {
            let gmac = GmacVt::new(Aes128::new(&key16));
            let tag = gmac.compute(nonce, message);
            tag_binds(
                "GMAC-AES-128 (variable time)",
                message,
                &tag,
                at,
                bit,
                |m, t| gmac.verify(nonce, m, t),
            );
            assert_eq!(
                tag,
                Gmac::new(Aes128::new(&key16)).compute(nonce, message),
                "GMAC back ends differ"
            );
        }
        _ => {
            // Poly1305 binds the message with probability about
            // 1 − 8⌈L/16⌉/2^106 over a uniform key, not for every key: a
            // small `r` collides (r = 2^48 already does on two blocks), so
            // the key is a digest of the input bytes rather than the bytes.
            let hashed: [u8; 32] = Sha256::digest(&key).as_ref().try_into().expect("32 bytes");
            let poly = Poly1305::new(&hashed);
            let tag = poly.compute(message);
            tag_binds("Poly1305", message, &tag, at, bit, |m, t| {
                let Ok(t) = <[u8; 16]>::try_from(t) else {
                    return false;
                };
                poly.verify(m, &t)
            });
        }
    }
});
