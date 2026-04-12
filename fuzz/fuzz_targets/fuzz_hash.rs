//! Fuzz all hash functions: one-shot digest must equal incremental
//! update/finalize on the same data broken into variable-size chunks.
//!
//! Also verifies HMAC consistency (compute == new+update+finalize) and
//! HKDF consistency (derive == extract+expand).
#![no_main]

use cryptography::{Hkdf, Hmac, Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Sha3_256, Sha3_512};
use libfuzzer_sys::fuzz_target;

macro_rules! check_hash {
    ($T:ty, $data:expr, $step:expr) => {{
        let whole = <$T>::digest($data);
        let mut h = <$T>::new();
        for chunk in $data.chunks($step) {
            h.update(chunk);
        }
        let incr = h.finalize();
        assert_eq!(
            whole, incr,
            concat!(stringify!($T), ": digest() != incremental update+finalize"),
        );
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let step = (data[0] as usize % 64) + 1;
    let payload = &data[1..];

    // Each hash: one-shot == incremental.
    check_hash!(Md5, payload, step);
    check_hash!(Sha1, payload, step);
    check_hash!(Sha224, payload, step);
    check_hash!(Sha256, payload, step);
    check_hash!(Sha384, payload, step);
    check_hash!(Sha512, payload, step);
    check_hash!(Sha3_256, payload, step);
    check_hash!(Sha3_512, payload, step);

    // HMAC-SHA256: Hmac::compute == incremental new+update+finalize.
    let key = payload.get(..16).unwrap_or(payload);
    let mac_whole = Hmac::<Sha256>::compute(key, payload);
    let mut hm = Hmac::<Sha256>::new(key);
    for chunk in payload.chunks(step) {
        hm.update(chunk);
    }
    let mac_incr = hm.finalize();
    assert_eq!(mac_whole, mac_incr, "HMAC-SHA256: compute != incremental");

    // HMAC verify must accept its own tag.
    assert!(
        Hmac::<Sha256>::verify(key, payload, &mac_whole),
        "HMAC-SHA256: verify rejected its own tag",
    );

    // HKDF-SHA256: derive == extract+expand.
    let salt = payload.get(..8).unwrap_or(payload);
    let out_len = step; // 1-64 bytes, always within HKDF limits
    if let Some(derived) = Hkdf::<Sha256>::derive(Some(salt), payload, b"fuzz", out_len) {
        let hk = Hkdf::<Sha256>::extract(Some(salt), payload);
        let mut expanded = vec![0u8; out_len];
        let ok = hk.expand(b"fuzz", &mut expanded);
        assert!(ok, "HKDF-SHA256: expand returned false");
        assert_eq!(derived, expanded, "HKDF-SHA256: derive != extract+expand");
    }
});
