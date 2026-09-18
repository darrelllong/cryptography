//! HPKE (RFC 9180) setup, sealing and opening on arbitrary inputs.
//!
//! Layout: `[selector][ikmR][ikmS][psk][info][aad][message][enc][ciphertext]`,
//! each variable-length field taken from the remaining bytes by a length byte.
//! The selector picks the AEAD and the mode.
//!
//! What must hold: a context opens what the matching context sealed, and
//! nothing else. So the round trip is checked, and then the fuzzer's own `enc`
//! and ciphertext are handed to a receiver, which must either refuse or — in
//! the vanishing case where the fuzzer found a valid pair — return a plaintext
//! without the sealed one's associated data being reused. A refused `open`
//! must not advance the sequence number, or the next legitimate message would
//! be opened under the wrong nonce.
#![no_main]

use cryptography::vt::{Hpke, HpkeAead};
use cryptography::{Shake256, Xof};
use libfuzzer_sys::fuzz_target;

/// Take a length-prefixed slice, capped so one field cannot eat the input.
fn take<'a>(data: &mut &'a [u8], cap: usize) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(cap).min(rest.len());
    let (field, tail) = rest.split_at(len);
    *data = tail;
    field
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    data = rest;

    let aead = match selector % 3 {
        0 => HpkeAead::Aes128Gcm,
        1 => HpkeAead::Aes256Gcm,
        _ => HpkeAead::ChaCha20Poly1305,
    };
    let mode = (selector / 3) % 4;

    let recipient_ikm = take(&mut data, 64);
    let sender_ikm = take(&mut data, 64);
    let psk = take(&mut data, 64);
    let psk_id = take(&mut data, 64);
    let info = take(&mut data, 64);
    let aad = take(&mut data, 64);
    let message = take(&mut data, 128);
    let offered_enc = take(&mut data, 64);
    let offered_ciphertext = data;

    let Some((recipient, recipient_public)) = Hpke::derive_key_pair(recipient_ikm) else {
        return;
    };
    let Some((sender, sender_public)) = Hpke::derive_key_pair(sender_ikm) else {
        return;
    };
    // DeriveKeyPair is a function: the same seed gives the same key.
    assert_eq!(
        Hpke::derive_key_pair(recipient_ikm).map(|(_, public)| public),
        Some(recipient_public),
        "DeriveKeyPair is deterministic"
    );

    // The RFC's PSK modes require a key and an identifier together; the others
    // require neither. An empty pair in a PSK mode has no valid setup, so the
    // round trip below would have nothing to check.
    let psk_mode = mode == 1 || mode == 3;
    if psk_mode && (psk.is_empty() || psk_id.is_empty()) {
        return;
    }

    // The sender's ephemeral key is drawn from a generator; reuse the sender's
    // own seed material so a given input is reproducible.
    let mut ephemeral = Ephemeral::new(sender_ikm);

    let setup = match mode {
        0 => Hpke::setup_sender(aead, &recipient_public, info, &mut ephemeral),
        1 => Hpke::setup_sender_psk(aead, &recipient_public, info, psk, psk_id, &mut ephemeral),
        2 => Hpke::setup_sender_auth(aead, &recipient_public, info, &sender, &mut ephemeral),
        _ => Hpke::setup_sender_auth_psk(
            aead,
            &recipient_public,
            info,
            psk,
            psk_id,
            &sender,
            &mut ephemeral,
        ),
    };
    let Some((enc, mut sender_context)) = setup else {
        return;
    };

    let receiver = |enc: &[u8]| match mode {
        0 => Hpke::setup_receiver(aead, enc, &recipient, info),
        1 => Hpke::setup_receiver_psk(aead, enc, &recipient, info, psk, psk_id),
        2 => Hpke::setup_receiver_auth(aead, enc, &recipient, info, &sender_public),
        _ => Hpke::setup_receiver_auth_psk(aead, enc, &recipient, info, psk, psk_id, &sender_public),
    };

    let Some(mut receiver_context) = receiver(&enc) else {
        panic!("the receiver refused an encapsulation its own sender produced");
    };

    let sealed = sender_context.seal(aad, message).expect("seal");
    assert_eq!(
        sealed.len(),
        message.len() + 16,
        "the ciphertext carries the message and a 128-bit tag"
    );

    // A tampered tag must be refused without moving the sequence number, so
    // the message that follows still opens.
    let mut altered = sealed.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x80;
    assert!(
        receiver_context.open(aad, &altered).is_none(),
        "a tampered ciphertext opened"
    );
    assert_eq!(receiver_context.sequence(), 0, "a refusal moved the sequence");

    let opened = receiver_context.open(aad, &sealed).expect("open");
    assert_eq!(opened, message, "the round trip lost the message");
    assert_eq!(sender_context.sequence(), receiver_context.sequence());

    // Exports agree on both sides, and the length is honoured.
    let exported = sender_context.export(aad, 32).expect("export");
    assert_eq!(exported.len(), 32);
    assert_eq!(receiver_context.export(aad, 32), Some(exported));

    // The fuzzer's own encapsulation and ciphertext: whatever they are, the
    // library must either refuse or return without panicking, and a receiver
    // built from a different encapsulation must not open the sealed message.
    if let Some(mut other) = receiver(offered_enc) {
        if offered_enc != enc.as_slice() {
            assert!(
                other.open(aad, &sealed).is_none(),
                "a foreign encapsulation opened the message"
            );
        }
        let _ = other.open(aad, offered_ciphertext);
    }
    let _ = Hpke::open(aead, offered_enc, &recipient, info, aad, offered_ciphertext);
});

/// A generator that expands the input's own bytes with SHAKE256, so the
/// ephemeral key is a function of the fuzzer's input and a crash replays
/// exactly. The domain string keeps this expansion from colliding with any
/// other use of the same seed.
struct Ephemeral(Shake256);

impl Ephemeral {
    fn new(seed: &[u8]) -> Self {
        let mut xof = Shake256::new();
        xof.update(b"fuzz_hpke ephemeral");
        xof.update(seed);
        Self(xof)
    }
}

impl cryptography::Csprng for Ephemeral {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}
