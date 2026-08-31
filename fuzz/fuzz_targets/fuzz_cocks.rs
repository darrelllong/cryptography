//! Fuzz Cocks IBE: encrypt/decrypt roundtrip.
//!
//! Uses hardcoded primes p ≡ q ≡ 3 (mod 4) so encryption is always
//! exercisable.  The message is arbitrary bytes from the corpus.
//!
//! Invariant: decrypt(encrypt(msg)) == msg
#![no_main]

use cryptography::public_key::{
    cocks::{Cocks, CocksPrivateKey, CocksPublicKey},
};
use cryptography::vt::BigUint;
// Note: encrypt(msg) converts msg bytes to a BigUint (strips leading zeros).
// decrypt returns the canonical big-endian bytes of that BigUint (also no
// leading zeros).  The roundtrip therefore preserves the *integer* value, not
// the original byte string.  We compare BigUint values, not byte slices.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(CocksPublicKey, CocksPrivateKey)> = OnceLock::new();

fn key() -> &'static (CocksPublicKey, CocksPrivateKey) {
    KEY.get_or_init(|| {
        let p = BigUint::from_u64(1019);
        let q = BigUint::from_u64(1031);
        Cocks::from_primes(&p, &q).expect("Cocks keygen with p=1019,q=1031 failed")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (pk, sk) = key();

    if let Some(ct) = pk.encrypt(data) {
        let recovered = sk.decrypt(&ct);
        // Compare the integer values: leading-zero bytes in `data` are stripped
        // by from_be_bytes, so the byte slices may differ even on a correct
        // roundtrip.
        let msg_int = BigUint::from_be_bytes(data);
        let rec_int = BigUint::from_be_bytes(&recovered);
        assert_eq!(rec_int, msg_int, "Cocks: decrypt(encrypt(msg)) integer mismatch");
    }
});
