//! One-off helper that prints a SHA-256 digest of `pk || sk_wire || ct`
//! for each IEEE 1363.1 NTRUEncrypt parameter set, driving the AES-256
//! CTR-DRBG from the fixed seed `[0xC0; 48]` and encrypting the fixed
//! payload `[0xA5; 8]`. The digest is the regression fingerprint baked
//! into each per-set file so a future refactor that silently changes
//! byte-level encoding of pk / sk / ct fails immediately.
//!
//! Run with `cargo run --bin ees_regression_gen` to refresh the
//! constants; copy the printed `digest = "<hex>"` line into the
//! corresponding `crate::public_key::ntru_ees_core::define_ees_set!`
//! invocation in each per-set source file.

use cryptography::hash::sha2::Sha256;
use cryptography::vt::{
    NtruEes1087Ep1, NtruEes1087Ep2, NtruEes1171Ep1, NtruEes1499Ep1, NtruEes401Ep1, NtruEes443Ep1,
    NtruEes449Ep1, NtruEes541Ep1, NtruEes677Ep1,
};
use cryptography::CtrDrbgAes256;

const SEED: [u8; 48] = [0xC0; 48];
const MSG: [u8; 8] = [0xA5; 8];

fn print_digest(name: &str, pk: &[u8], sk: &[u8], ct: &[u8]) {
    let mut h = Sha256::new();
    h.update(pk);
    h.update(sk);
    h.update(ct);
    let d = h.finalize();
    print!("{name}: ");
    for b in d.iter() {
        print!("{b:02x}");
    }
    println!();
}

macro_rules! run {
    ($ty:ty, $name:literal) => {{
        let mut drbg = CtrDrbgAes256::new(&SEED);
        let (pk, sk) = <$ty>::keygen(&mut drbg);
        let ct = <$ty>::encrypt(&pk, &MSG, &mut drbg).expect("encrypt");
        print_digest(
            $name,
            &pk.to_wire_bytes(),
            &sk.to_wire_bytes(),
            &ct.to_wire_bytes(),
        );
    }};
}

fn main() {
    run!(NtruEes401Ep1, "NtruEes401Ep1");
    run!(NtruEes443Ep1, "NtruEes443Ep1");
    run!(NtruEes449Ep1, "NtruEes449Ep1");
    run!(NtruEes541Ep1, "NtruEes541Ep1");
    run!(NtruEes677Ep1, "NtruEes677Ep1");
    run!(NtruEes1087Ep1, "NtruEes1087Ep1");
    run!(NtruEes1087Ep2, "NtruEes1087Ep2");
    run!(NtruEes1171Ep1, "NtruEes1171Ep1");
    run!(NtruEes1499Ep1, "NtruEes1499Ep1");
}
