//! Fuzz Rabin: encrypt_raw/decrypt_raw roundtrip.
//!
//! Uses hardcoded Blum primes (p ≡ q ≡ 3 mod 4) so the crypto operations are
//! always exercised.  The message is one byte to stay well below n.
//!
//! Invariant: decrypt_raw(encrypt_raw(m)) == Some(m)
#![no_main]

use cryptography::public_key::{
    rabin::{Rabin, RabinPrivateKey, RabinPublicKey},
};
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(RabinPublicKey, RabinPrivateKey)> = OnceLock::new();

fn key() -> &'static (RabinPublicKey, RabinPrivateKey) {
    KEY.get_or_init(|| {
        // 1019 ≡ 3 (mod 4), prime; 1031 ≡ 3 (mod 4), prime; n = 1 050 589.
        let p = BigUint::from_u64(1019);
        let q = BigUint::from_u64(1031);
        Rabin::from_primes(&p, &q).expect("Rabin keygen with p=1019,q=1031 failed")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (pk, sk) = key();
    // Keep message well below n = 1 050 589 by using a single byte (1–256).
    let msg = BigUint::from_u64(data[0] as u64 + 1);

    if let Some(ct) = pk.encrypt_raw(&msg) {
        let recovered = sk.decrypt_raw(&ct);
        assert_eq!(
            recovered,
            Some(msg),
            "Rabin: decrypt_raw(encrypt_raw(m)) != Some(m)",
        );
    }
});
