//! Fuzz Schmidt-Samoa: encrypt/decrypt roundtrip.
//!
//! Uses hardcoded primes.  Invariant: decrypt(encrypt(msg)) == msg.
#![no_main]

use cryptography::public_key::{
    bigint::BigUint,
    schmidt_samoa::{SchmidtSamoa, SchmidtSamoaPrivateKey, SchmidtSamoaPublicKey},
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<(SchmidtSamoaPublicKey, SchmidtSamoaPrivateKey)> = OnceLock::new();

fn key() -> &'static (SchmidtSamoaPublicKey, SchmidtSamoaPrivateKey) {
    KEY.get_or_init(|| {
        let p = BigUint::from_u64(1009);
        let q = BigUint::from_u64(1013);
        SchmidtSamoa::from_primes(&p, &q)
            .expect("SchmidtSamoa keygen with p=1009,q=1013 failed")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (pk, sk) = key();

    if let Some(ct) = pk.encrypt(data) {
        let recovered = sk.decrypt(&ct);
        // encrypt strips leading zeros via from_be_bytes; compare integers.
        let msg_int = BigUint::from_be_bytes(data);
        let rec_int = BigUint::from_be_bytes(&recovered);
        assert_eq!(
            rec_int, msg_int,
            "Schmidt-Samoa: decrypt(encrypt(msg)) integer mismatch",
        );
    }
});
