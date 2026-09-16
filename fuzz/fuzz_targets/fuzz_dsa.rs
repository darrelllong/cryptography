//! DSA from a fuzzer-supplied private key: parse a key blob, sign a digest
//! under a fuzzer-chosen nonce, and verify.
//!
//! Layout: `[u16 blob length][private-key blob][32-byte nonce][digest]`.
//! `fuzz/seeds/fuzz_dsa` seeds the blob with toy keys, since a valid blob is
//! not found by mutation. The nonce bytes are shifted down to the bit width
//! of `q`, so about half the draws are in range. The digest is reduced the
//! way FIPS 186-4 §4.6 and
//! §4.7 reduce it, to its leftmost `min(N, outlen)` bits with `N = bits(q)`,
//! so `verify_digest_scalar` sees what `sign_digest_with_nonce` signed; a
//! digest with one flipped bit must not verify.
#![no_main]

use cryptography::public_key::dsa::DsaPrivateKey;
use cryptography::vt::BigUint;
use libfuzzer_sys::fuzz_target;

/// FIPS 186-4 §4.6 step 2: the leftmost `min(N, outlen)` bits of the digest.
fn digest_representative(digest: &[u8], q_bits: usize) -> BigUint {
    let mut value = BigUint::from_be_bytes(digest);
    let digest_bits = digest.len() * 8;
    if digest_bits > q_bits {
        value.shr_bits(digest_bits - q_bits);
    }
    value
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let blob_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[2..];
    if rest.len() < blob_len + 32 {
        return;
    }
    let (blob, rest) = rest.split_at(blob_len);
    let (nonce, digest) = rest.split_at(32);

    let Some(sk) = DsaPrivateKey::from_key_blob(blob) else {
        return;
    };
    let pk = sk.to_public_key();
    let q_bits = pk.subgroup_order().bits();
    let mut nonce = BigUint::from_be_bytes(nonce);
    if 256 > q_bits {
        nonce.shr_bits(256 - q_bits);
    }
    let Some(sig) = sk.sign_digest_with_nonce(digest, &nonce) else {
        return;
    };
    assert!(
        pk.verify_digest_scalar(&digest_representative(digest, q_bits), &sig),
        "DSA: the honest signature verifies"
    );
    if !digest.is_empty() {
        let mut bad = digest.to_vec();
        bad[0] ^= 1;
        assert!(
            !pk.verify_digest_scalar(&digest_representative(&bad, q_bits), &sig),
            "DSA: a flipped digest verified"
        );
    }
    let der = sig.to_der();
    let again =
        cryptography::public_key::dsa::DsaSignature::from_der(&der).expect("own DER parses");
    assert_eq!(again.to_der(), der, "DSA: Dss-Sig-Value re-encodes");
});
