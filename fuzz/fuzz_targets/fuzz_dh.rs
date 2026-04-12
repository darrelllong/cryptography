//! Fuzz DH: parse a private-key blob and exercise agree_element.
//!
//! The first half is tried as a DH private-key blob.  If valid, self-agreement
//! (sk.agree(sk.public_key)) is checked for no-panic.  The second half is
//! tried as a peer public-key blob; if that also parses, cross-agreement is
//! exercised.  Both calls must not panic regardless of group-parameter
//! compatibility.
#![no_main]

use cryptography::public_key::dh::{DhPrivateKey, DhPublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let mid = data.len() / 2;
    let (blob1, blob2) = data.split_at(mid);

    let sk = match DhPrivateKey::from_key_blob(blob1) {
        Some(k) => k,
        None => return,
    };

    // Self-agreement: must not panic.
    let my_pk = sk.to_public_key();
    let _ = sk.agree_element(&my_pk);

    // Cross-agreement with arbitrary peer: must not panic.
    if let Some(peer_pk) = DhPublicKey::from_key_blob(blob2) {
        let _ = sk.agree_element(&peer_pk);
    }
});
