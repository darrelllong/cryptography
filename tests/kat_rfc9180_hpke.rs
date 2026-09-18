//! RFC 9180 (HPKE) known answers for the two DHKEM(X25519, HKDF-SHA256)
//! suites of Appendix A.1 and A.2, through the public API.
//!
//! Each case runs both sides: a sender context built with the appendix's own
//! ephemeral key seals the two messages of the suite's "Encryptions"
//! subsection and must produce its ciphertexts, and a receiver context built
//! from the encapsulation alone must open them and export the three values of
//! its "Exported Values" subsection. The key schedule's intermediate values are
//! checked where they live, in the module's own tests.

mod common;

use common::{decode_hex, parse_vector_map};
use cryptography::vt::{Hpke, HpkeAead, X25519PrivateKey, X25519PublicKey};
use cryptography::Csprng;
use std::collections::HashMap;

const VECTORS: &str = include_str!("vectors/hpke_rfc9180.txt");

/// A source that hands out one fixed value. HPKE's sender setup draws the
/// ephemeral scalar from the caller's generator, so supplying the appendix's
/// `skEm` reproduces its encapsulation exactly; nothing else in these cases
/// draws from it.
struct FixedSource(Vec<u8>);

impl Csprng for FixedSource {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        assert_eq!(
            out.len(),
            self.0.len(),
            "an unexpected draw from the source"
        );
        out.copy_from_slice(&self.0);
    }
}

fn field(map: &HashMap<&str, &str>, tag: &str, name: &str) -> Vec<u8> {
    let key = format!("{tag}_{name}");
    decode_hex(
        map.get(key.as_str())
            .unwrap_or_else(|| panic!("{key} in the vector file")),
    )
}

/// A field the mode may not have: the PSK and its identifier outside the PSK
/// modes, the sender's key outside the auth modes.
fn optional(map: &HashMap<&str, &str>, tag: &str, name: &str) -> Vec<u8> {
    map.get(format!("{tag}_{name}").as_str())
        .map(|hex| decode_hex(hex))
        .unwrap_or_default()
}

fn private_key(bytes: &[u8]) -> X25519PrivateKey {
    X25519PrivateKey::from_raw_bytes(bytes.try_into().expect("a 32-byte scalar"))
}

fn public_key(bytes: &[u8]) -> X25519PublicKey {
    X25519PublicKey::from_raw_bytes(bytes.try_into().expect("a 32-byte u-coordinate"))
}

/// Run one appendix subsection end to end. `tag` names the suite and mode as
/// the vector file spells them, for instance `AESGCM128_BASE`.
fn case(tag: &str, aead: HpkeAead) {
    let map = parse_vector_map(VECTORS);
    let info = field(&map, tag, "INFO");
    let psk = optional(&map, tag, "PSK");
    let psk_id = optional(&map, tag, "PSK_ID");
    let sender_private = optional(&map, tag, "SKSM");
    let expected_enc = field(&map, tag, "ENC");

    // The recipient's key pair comes from the appendix's ikmR, so a wrong
    // derivation fails here rather than as a wrong ciphertext.
    let (recipient, recipient_public) =
        Hpke::derive_key_pair(&field(&map, tag, "IKMR")).expect("the recipient key pair");
    assert_eq!(
        recipient_public.to_raw_bytes().to_vec(),
        field(&map, tag, "PKRM"),
        "{tag}: pkRm"
    );

    let mut ephemeral = FixedSource(field(&map, tag, "SKEM"));
    let (enc, mut sender) = match (psk.is_empty(), sender_private.is_empty()) {
        (true, true) => Hpke::setup_sender(aead, &recipient_public, &info, &mut ephemeral),
        (false, true) => Hpke::setup_sender_psk(
            aead,
            &recipient_public,
            &info,
            &psk,
            &psk_id,
            &mut ephemeral,
        ),
        (true, false) => Hpke::setup_sender_auth(
            aead,
            &recipient_public,
            &info,
            &private_key(&sender_private),
            &mut ephemeral,
        ),
        (false, false) => Hpke::setup_sender_auth_psk(
            aead,
            &recipient_public,
            &info,
            &psk,
            &psk_id,
            &private_key(&sender_private),
            &mut ephemeral,
        ),
    }
    .unwrap_or_else(|| panic!("{tag}: the sender context"));
    assert_eq!(enc.to_vec(), expected_enc, "{tag}: enc");

    let mut receiver = match (psk.is_empty(), sender_private.is_empty()) {
        (true, true) => Hpke::setup_receiver(aead, &enc, &recipient, &info),
        (false, true) => Hpke::setup_receiver_psk(aead, &enc, &recipient, &info, &psk, &psk_id),
        (true, false) => Hpke::setup_receiver_auth(
            aead,
            &enc,
            &recipient,
            &info,
            &public_key(&field(&map, tag, "PKSM")),
        ),
        (false, false) => Hpke::setup_receiver_auth_psk(
            aead,
            &enc,
            &recipient,
            &info,
            &psk,
            &psk_id,
            &public_key(&field(&map, tag, "PKSM")),
        ),
    }
    .unwrap_or_else(|| panic!("{tag}: the receiver context"));

    // The sequence number is part of the nonce, so the two records must be
    // sealed and opened in the order the appendix lists them.
    for sequence in 0..2u64 {
        let plaintext = field(&map, tag, &format!("SEQ{sequence}_PT"));
        let aad = field(&map, tag, &format!("SEQ{sequence}_AAD"));
        let ciphertext = field(&map, tag, &format!("SEQ{sequence}_CT"));

        assert_eq!(sender.sequence(), sequence, "{tag}: the sender's sequence");
        let sealed = sender
            .seal(&aad, &plaintext)
            .unwrap_or_else(|| panic!("{tag}: sealing record {sequence}"));
        assert_eq!(sealed, ciphertext, "{tag}: ciphertext {sequence}");

        assert_eq!(
            receiver.sequence(),
            sequence,
            "{tag}: the receiver's sequence"
        );
        let opened = receiver
            .open(&aad, &ciphertext)
            .unwrap_or_else(|| panic!("{tag}: opening record {sequence}"));
        assert_eq!(opened, plaintext, "{tag}: plaintext {sequence}");
    }

    // Exports are independent of the sequence number and both sides must agree
    // on them.
    for which in 0..3 {
        let context = optional(&map, tag, &format!("EXPORT{which}_CONTEXT"));
        let key = format!("{tag}_EXPORT{which}_L");
        let len: usize = map
            .get(key.as_str())
            .unwrap_or_else(|| panic!("{key} in the vector file"))
            .parse()
            .expect("an export length");
        let expected = field(&map, tag, &format!("EXPORT{which}_VALUE"));

        let exported = receiver
            .export(&context, len)
            .unwrap_or_else(|| panic!("{tag}: export {which}"));
        assert_eq!(exported, expected, "{tag}: exported value {which}");
        assert_eq!(
            sender.export(&context, len),
            Some(expected),
            "{tag}: the sender's export {which}"
        );
    }
}

#[test]
fn appendix_a1_aes_128_gcm_base() {
    case("AESGCM128_BASE", HpkeAead::Aes128Gcm);
}

#[test]
fn appendix_a1_aes_128_gcm_psk() {
    case("AESGCM128_PSK", HpkeAead::Aes128Gcm);
}

#[test]
fn appendix_a1_aes_128_gcm_auth() {
    case("AESGCM128_AUTH", HpkeAead::Aes128Gcm);
}

#[test]
fn appendix_a1_aes_128_gcm_auth_psk() {
    case("AESGCM128_AUTHPSK", HpkeAead::Aes128Gcm);
}

#[test]
fn appendix_a2_chacha20poly1305_base() {
    case("CHACHA20POLY1305_BASE", HpkeAead::ChaCha20Poly1305);
}

#[test]
fn appendix_a2_chacha20poly1305_psk() {
    case("CHACHA20POLY1305_PSK", HpkeAead::ChaCha20Poly1305);
}

#[test]
fn appendix_a2_chacha20poly1305_auth() {
    case("CHACHA20POLY1305_AUTH", HpkeAead::ChaCha20Poly1305);
}

#[test]
fn appendix_a2_chacha20poly1305_auth_psk() {
    case("CHACHA20POLY1305_AUTHPSK", HpkeAead::ChaCha20Poly1305);
}

/// A tampered ciphertext, a wrong `enc`, wrong associated data and a wrong
/// info string each refuse, rather than returning a plaintext.
#[test]
fn a_changed_field_refuses_to_open() {
    let map = parse_vector_map(VECTORS);
    let tag = "AESGCM128_BASE";
    let aead = HpkeAead::Aes128Gcm;
    let info = field(&map, tag, "INFO");
    let aad = field(&map, tag, "SEQ0_AAD");
    let enc = field(&map, tag, "ENC");
    let ciphertext = field(&map, tag, "SEQ0_CT");
    let recipient = private_key(&field(&map, tag, "SKRM"));

    assert!(Hpke::open(aead, &enc, &recipient, &info, &aad, &ciphertext).is_some());

    let mut altered = ciphertext.clone();
    altered[0] ^= 1;
    assert!(Hpke::open(aead, &enc, &recipient, &info, &aad, &altered).is_none());

    let mut wrong_enc = enc.clone();
    wrong_enc[0] ^= 1;
    assert!(Hpke::open(aead, &wrong_enc, &recipient, &info, &aad, &ciphertext).is_none());

    let mut wrong_aad = aad.clone();
    wrong_aad[0] ^= 1;
    assert!(Hpke::open(aead, &enc, &recipient, &info, &wrong_aad, &ciphertext).is_none());

    let mut wrong_info = info.clone();
    wrong_info[0] ^= 1;
    assert!(Hpke::open(aead, &enc, &recipient, &wrong_info, &aad, &ciphertext).is_none());

    // A truncated ciphertext cannot even carry a tag.
    assert!(Hpke::open(aead, &enc, &recipient, &info, &aad, &ciphertext[..8]).is_none());
}

/// An encapsulation naming a low-order point drives the agreement to the
/// all-zero shared secret, which RFC 7748 §6.1 says to reject: no context is
/// built at all, in any mode.
#[test]
fn a_low_order_encapsulation_is_refused() {
    let map = parse_vector_map(VECTORS);
    let tag = "AESGCM128_BASE";
    let aead = HpkeAead::Aes128Gcm;
    let info = field(&map, tag, "INFO");
    let recipient = private_key(&field(&map, tag, "SKRM"));
    let sender_public = public_key(&field(&map, tag, "PKEM"));
    let psk = field(&map, "AESGCM128_PSK", "PSK");
    let psk_id = field(&map, "AESGCM128_PSK", "PSK_ID");

    // The order-1 and order-2 u-coordinates of Curve25519, and the order-8
    // point RFC 7748 §6.1 lists first.
    let low_order: [[u8; 32]; 3] = [
        [0u8; 32],
        {
            let mut u = [0u8; 32];
            u[0] = 1;
            u
        },
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
    ];

    for enc in &low_order {
        assert!(
            Hpke::setup_receiver(aead, enc, &recipient, &info).is_none(),
            "base mode accepted a low-order encapsulation"
        );
        assert!(
            Hpke::setup_receiver_psk(aead, enc, &recipient, &info, &psk, &psk_id).is_none(),
            "PSK mode accepted a low-order encapsulation"
        );
        assert!(
            Hpke::setup_receiver_auth(aead, enc, &recipient, &info, &sender_public).is_none(),
            "auth mode accepted a low-order encapsulation"
        );
    }

    // An encapsulation of the wrong length is not a u-coordinate at all.
    assert!(Hpke::setup_receiver(aead, &[0u8; 31], &recipient, &info).is_none());
    assert!(Hpke::setup_receiver(aead, &[0u8; 33], &recipient, &info).is_none());
}

/// The wrong recipient key, and in auth mode the wrong sender key, yield a
/// context that cannot open the message.
#[test]
fn a_wrong_key_cannot_open() {
    let map = parse_vector_map(VECTORS);
    let aead = HpkeAead::Aes128Gcm;

    let tag = "AESGCM128_BASE";
    let info = field(&map, tag, "INFO");
    let aad = field(&map, tag, "SEQ0_AAD");
    let enc = field(&map, tag, "ENC");
    let ciphertext = field(&map, tag, "SEQ0_CT");
    let (other, _) = Hpke::derive_key_pair(b"a key that was not the recipient's").expect("a pair");
    assert!(Hpke::open(aead, &enc, &other, &info, &aad, &ciphertext).is_none());

    let tag = "AESGCM128_AUTH";
    let info = field(&map, tag, "INFO");
    let aad = field(&map, tag, "SEQ0_AAD");
    let enc = field(&map, tag, "ENC");
    let ciphertext = field(&map, tag, "SEQ0_CT");
    let recipient = private_key(&field(&map, tag, "SKRM"));
    let (_, wrong_sender) =
        Hpke::derive_key_pair(b"a key that was not the sender's").expect("a pair");
    let mut context = Hpke::setup_receiver_auth(aead, &enc, &recipient, &info, &wrong_sender)
        .expect("a context, since the KEM cannot tell which sender key is meant");
    assert!(context.open(&aad, &ciphertext).is_none());
}
