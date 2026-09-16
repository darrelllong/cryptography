//! Every hash function and XOF in the crate: the one-shot digest equals the
//! digest of the same bytes fed in chunks of a fuzzer-chosen size; a XOF
//! squeezed in two parts equals the same length squeezed at once; HMAC and
//! HKDF agree with their one-shot forms.
#![no_main]

use cryptography::{
    Hkdf, Hmac, Md5, Ripemd160, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, Sha512, Sha512_224, Sha512_256, Shake128, Shake256, Xof,
};
use libfuzzer_sys::fuzz_target;

macro_rules! check_hash {
    ($T:ty, $data:expr, $step:expr) => {{
        let whole = <$T>::digest($data);
        let mut h = <$T>::new();
        for chunk in $data.chunks($step) {
            h.update(chunk);
        }
        assert_eq!(
            whole,
            h.finalize(),
            concat!(stringify!($T), ": streaming differs from one-shot")
        );
    }};
}

macro_rules! check_xof {
    ($T:ty, $data:expr, $step:expr, $split:expr) => {{
        let mut whole = <$T>::new();
        whole.update($data);
        let mut at_once = [0u8; 96];
        whole.squeeze(&mut at_once);

        let mut streamed = <$T>::new();
        for chunk in $data.chunks($step) {
            streamed.update(chunk);
        }
        let mut in_parts = [0u8; 96];
        let (head, tail) = in_parts.split_at_mut($split);
        streamed.squeeze(head);
        streamed.squeeze(tail);
        assert_eq!(
            at_once, in_parts,
            concat!(stringify!($T), ": output depends on how it was squeezed")
        );
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let step = usize::from(data[0] % 64) + 1;
    let split = usize::from(data[1]) % 97;
    let payload = &data[2..];

    check_hash!(Md5, payload, step);
    check_hash!(Ripemd160, payload, step);
    check_hash!(Sha1, payload, step);
    check_hash!(Sha224, payload, step);
    check_hash!(Sha256, payload, step);
    check_hash!(Sha384, payload, step);
    check_hash!(Sha512, payload, step);
    check_hash!(Sha512_224, payload, step);
    check_hash!(Sha512_256, payload, step);
    check_hash!(Sha3_224, payload, step);
    check_hash!(Sha3_256, payload, step);
    check_hash!(Sha3_384, payload, step);
    check_hash!(Sha3_512, payload, step);
    check_xof!(Shake128, payload, step, split);
    check_xof!(Shake256, payload, step, split);

    let key = payload.get(..16).unwrap_or(payload);
    let mac_whole = Hmac::<Sha256>::compute(key, payload);
    let mut hm = Hmac::<Sha256>::new(key);
    for chunk in payload.chunks(step) {
        hm.update(chunk);
    }
    assert_eq!(
        mac_whole,
        hm.finalize(),
        "HMAC-SHA-256: streaming differs from one-shot"
    );
    assert!(
        Hmac::<Sha256>::verify(key, payload, &mac_whole),
        "HMAC-SHA-256: refused its own tag"
    );

    let salt = payload.get(..8).unwrap_or(payload);
    let out_len = step;
    if let Some(derived) = Hkdf::<Sha256>::derive(Some(salt), payload, b"fuzz", out_len) {
        let hk = Hkdf::<Sha256>::extract(Some(salt), payload);
        let mut expanded = vec![0u8; out_len];
        assert!(
            hk.expand(b"fuzz", &mut expanded),
            "HKDF-SHA-256: expand refused a length derive accepted"
        );
        assert_eq!(
            derived, expanded,
            "HKDF-SHA-256: derive differs from extract + expand"
        );
    }
});
