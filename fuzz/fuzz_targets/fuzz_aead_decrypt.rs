//! Authenticated decryption under hostile input, for every AEAD in the crate:
//! GCM (both GHASH back ends), AES-GCM-SIV, CCM, OCB, SIV, EAX and
//! ChaCha20-Poly1305.
//!
//! Layout: `[mode][flip position][flip bit][key][nonce length byte][nonce]
//! [aad length byte][aad][plaintext]`. Nonce lengths are drawn inside each
//! mode's documented range (GCM 1..=16 bytes, CCM 7..=13, OCB 0..=15, SIV
//! and EAX 0..=32, the 96-bit modes exactly 12), since a length outside it
//! is a documented panic, not a decoder defect.
//!
//! Every mode must: open its own honest ciphertext to the plaintext; refuse
//! that ciphertext once one chosen bit of the ciphertext, of the tag, of the
//! AAD or of the nonce is flipped; refuse the payload itself presented as a
//! ciphertext under a tag taken from the payload (a forgery succeeds with
//! probability 2^-tag bits; the fuzzer never sees one); and, when it refuses,
//! leave the caller's buffer as it found it, so a caller that ignores the
//! `false` cannot read a decryption that was never authenticated.
#![no_main]

use cryptography::{
    Aead, Aes128, Aes128GcmSiv, Aes256, Ccm, ChaCha20Poly1305, Eax, Gcm, GcmVt, Ocb, Siv,
};
use libfuzzer_sys::fuzz_target;

const MODES: u8 = 8;

struct Input<'a> {
    flip_at: usize,
    flip_bit: u8,
    nonce: &'a [u8],
    aad: &'a [u8],
    plaintext: &'a [u8],
    hostile_tag: [u8; 16],
}

fn flip(buf: &mut [u8], at: usize, bit: u8) -> bool {
    if buf.is_empty() {
        return false;
    }
    let index = at % buf.len();
    buf[index] ^= 1 << (bit % 8);
    true
}

fn exercise<A: Aead>(name: &str, aead: &A, input: &Input<'_>)
where
    A::Tag: Clone + AsRef<[u8]> + AsMut<[u8]>,
{
    let Input {
        flip_at,
        flip_bit,
        nonce,
        aad,
        plaintext,
        hostile_tag,
    } = *input;
    let (ciphertext, tag) = aead.encrypt(nonce, aad, plaintext);
    assert_eq!(
        aead.decrypt(nonce, aad, &ciphertext, &tag).as_deref(),
        Some(plaintext),
        "{name}: refused its own ciphertext"
    );

    let mut bad = ciphertext.clone();
    if flip(&mut bad, flip_at, flip_bit) {
        assert!(
            aead.decrypt(nonce, aad, &bad, &tag).is_none(),
            "{name}: accepted a ciphertext with one flipped bit"
        );
    }
    let mut bad_tag = tag.clone();
    flip(bad_tag.as_mut(), flip_at, flip_bit);
    assert!(
        aead.decrypt(nonce, aad, &ciphertext, &bad_tag).is_none(),
        "{name}: accepted a tag with one flipped bit"
    );
    let mut bad_aad = aad.to_vec();
    if flip(&mut bad_aad, flip_at, flip_bit) {
        assert!(
            aead.decrypt(nonce, &bad_aad, &ciphertext, &tag).is_none(),
            "{name}: accepted AAD with one flipped bit"
        );
    }
    let mut bad_nonce = nonce.to_vec();
    if flip(&mut bad_nonce, flip_at, flip_bit) {
        assert!(
            aead.decrypt(&bad_nonce, aad, &ciphertext, &tag).is_none(),
            "{name}: accepted a nonce with one flipped bit"
        );
    }

    // A refusal must leave the caller's buffer untouched: `decrypt_in_place`
    // returns `false`, and what the buffer then holds is the ciphertext it was
    // given, not a plaintext nobody authenticated.
    let mut in_place = ciphertext.clone();
    let mut wrong_tag = tag.clone();
    flip(wrong_tag.as_mut(), flip_at, flip_bit);
    let opened = aead.decrypt_in_place(nonce, aad, &mut in_place, &wrong_tag);
    assert!(!opened, "{name}: accepted a tag with one flipped bit in place");
    assert_eq!(
        in_place, ciphertext,
        "{name}: a refused decryption changed the caller's buffer"
    );

    // The payload as a ciphertext under a tag from the payload.
    let mut forged = tag.clone();
    let width = forged.as_ref().len();
    forged.as_mut().copy_from_slice(&hostile_tag[..width]);
    if forged.as_ref() != tag.as_ref() || plaintext != ciphertext.as_slice() {
        assert!(
            aead.decrypt(nonce, aad, plaintext, &forged).is_none(),
            "{name}: accepted a forgery"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 + 32 + 1 + 1 {
        return;
    }
    let mode = data[0] % MODES;
    let flip_at = usize::from(data[1]);
    let flip_bit = data[2];
    let key: [u8; 32] = data[3..35].try_into().expect("32 bytes");
    let key16: [u8; 16] = key[..16].try_into().expect("16 bytes");
    let rest = &data[35..];

    let (nonce_len, aad_len) = match mode {
        0 | 1 => (1 + usize::from(rest[0] % 16), rest[1]),
        2 => (7 + usize::from(rest[0] % 7), rest[1]),
        3 => (usize::from(rest[0] % 16), rest[1]),
        4 | 5 => (usize::from(rest[0] % 33), rest[1]),
        _ => (12, rest[1]),
    };
    let rest = &rest[2..];
    if rest.len() < nonce_len {
        return;
    }
    let (nonce, rest) = rest.split_at(nonce_len);
    let aad_len = usize::from(aad_len).min(rest.len());
    let (aad, plaintext) = rest.split_at(aad_len);
    let mut hostile_tag = [0u8; 16];
    for (i, byte) in hostile_tag.iter_mut().enumerate() {
        *byte = plaintext.get(i).copied().unwrap_or(key[i]);
    }
    let input = Input {
        flip_at,
        flip_bit,
        nonce,
        aad,
        plaintext,
        hostile_tag,
    };

    match mode {
        0 => exercise("GCM-AES-256", &Gcm::new(Aes256::new(&key)), &input),
        1 => exercise(
            "GCM-AES-128 (variable time)",
            &GcmVt::new(Aes128::new(&key16)),
            &input,
        ),
        2 => exercise(
            "CCM-AES-128",
            &Ccm::<Aes128, 16>::new(Aes128::new(&key16)),
            &input,
        ),
        3 => exercise(
            "OCB-AES-128",
            &Ocb::<Aes128, 16>::new(Aes128::new(&key16)),
            &input,
        ),
        4 => {
            let mac_key: [u8; 16] = key[..16].try_into().expect("16 bytes");
            let ctr_key: [u8; 16] = key[16..].try_into().expect("16 bytes");
            exercise(
                "SIV-AES-128",
                &Siv::new(Aes128::new(&mac_key), Aes128::new(&ctr_key)),
                &input,
            )
        }
        5 => exercise("EAX-AES-128", &Eax::new(Aes128::new(&key16)), &input),
        6 => exercise("ChaCha20-Poly1305", &ChaCha20Poly1305::new(&key), &input),
        _ => exercise("AES-128-GCM-SIV", &Aes128GcmSiv::new(&key16), &input),
    }
});
