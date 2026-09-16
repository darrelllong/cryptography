//! NTRU under hostile ciphertexts: the nine EESS #1 NTRUEncrypt parameter
//! sets and the four NTRU round-3 KEMs.
//!
//! Layout: `[set][flip position][flip bit][48-byte DRBG seed][message]`. Keys
//! are generated once per set from a fixed seed; the DRBG seeded from the
//! input drives encryption. For NTRUEncrypt: decryption of an honest
//! ciphertext returns the message; the ciphertext with one flipped bit is
//! refused by the parser, refused by decryption, or decrypts to something
//! other than the message. For the KEMs: decapsulation of an honest
//! ciphertext returns the encapsulated secret, and of a ciphertext with one
//! flipped bit a different one (implicit rejection). Public keys and
//! ciphertexts re-encode to the bytes they were parsed from.
#![no_main]

use cryptography::vt::{
    NtruEes1087Ep1, NtruEes1087Ep1Ciphertext, NtruEes1087Ep1PrivateKey, NtruEes1087Ep1PublicKey,
    NtruEes1087Ep2, NtruEes1087Ep2Ciphertext, NtruEes1087Ep2PrivateKey, NtruEes1087Ep2PublicKey,
    NtruEes1171Ep1, NtruEes1171Ep1Ciphertext, NtruEes1171Ep1PrivateKey, NtruEes1171Ep1PublicKey,
    NtruEes1499Ep1, NtruEes1499Ep1Ciphertext, NtruEes1499Ep1PrivateKey, NtruEes1499Ep1PublicKey,
    NtruEes401Ep1, NtruEes401Ep1Ciphertext, NtruEes401Ep1PrivateKey, NtruEes401Ep1PublicKey,
    NtruEes443Ep1, NtruEes443Ep1Ciphertext, NtruEes443Ep1PrivateKey, NtruEes443Ep1PublicKey,
    NtruEes449Ep1, NtruEes449Ep1Ciphertext, NtruEes449Ep1PrivateKey, NtruEes449Ep1PublicKey,
    NtruEes541Ep1, NtruEes541Ep1Ciphertext, NtruEes541Ep1PrivateKey, NtruEes541Ep1PublicKey,
    NtruEes677Ep1, NtruEes677Ep1Ciphertext, NtruEes677Ep1PrivateKey, NtruEes677Ep1PublicKey,
    NtruHps509, NtruHps509Ciphertext, NtruHps509PrivateKey, NtruHps509PublicKey, NtruHps677,
    NtruHps677Ciphertext, NtruHps677PrivateKey, NtruHps677PublicKey, NtruHps821,
    NtruHps821Ciphertext, NtruHps821PrivateKey, NtruHps821PublicKey, NtruHrss701,
    NtruHrss701Ciphertext, NtruHrss701PrivateKey, NtruHrss701PublicKey,
};
use cryptography::CtrDrbgAes256;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const SETS: u8 = 13;
const SEED: usize = 48;

fn flipped(bytes: &[u8], at: usize, bit: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let index = at % out.len();
    out[index] ^= 1 << (bit % 8);
    out
}

macro_rules! ees {
    ($name:literal, $scheme:ty, $pk:ty, $sk:ty, $ct:ty, $rng:expr, $msg:expr, $at:expr, $bit:expr) => {{
        static KEY: OnceLock<($pk, $sk)> = OnceLock::new();
        let (pk, sk) =
            KEY.get_or_init(|| <$scheme>::keygen(&mut CtrDrbgAes256::new(&[0x5Au8; SEED])));
        let pk_bytes = pk.to_wire_bytes();
        let again =
            <$pk>::from_wire_bytes(&pk_bytes).expect(concat!($name, ": own public key parses"));
        assert_eq!(
            again.to_wire_bytes(),
            pk_bytes,
            concat!($name, ": public key re-encodes")
        );
        let Ok(ct) = <$scheme>::encrypt(pk, $msg, &mut $rng) else {
            return;
        };
        assert_eq!(
            <$scheme>::decrypt(sk, &ct).as_deref(),
            Ok($msg),
            concat!($name, ": honest ciphertext")
        );
        let ct_bytes = ct.to_wire_bytes();
        let again =
            <$ct>::from_wire_bytes(&ct_bytes).expect(concat!($name, ": own ciphertext parses"));
        assert_eq!(
            again.to_wire_bytes(),
            ct_bytes,
            concat!($name, ": ciphertext re-encodes")
        );
        if let Some(bad) = <$ct>::from_wire_bytes(&flipped(&ct_bytes, $at, $bit)) {
            if let Ok(plaintext) = <$scheme>::decrypt(sk, &bad) {
                assert_ne!(
                    plaintext, $msg,
                    concat!($name, ": a flipped ciphertext decrypted to the message")
                );
            }
        }
    }};
}

macro_rules! kem {
    ($name:literal, $scheme:ty, $pk:ty, $sk:ty, $ct:ty, $rng:expr, $at:expr, $bit:expr) => {{
        static KEY: OnceLock<($pk, $sk)> = OnceLock::new();
        let (pk, sk) =
            KEY.get_or_init(|| <$scheme>::keygen(&mut CtrDrbgAes256::new(&[0xA5u8; SEED])));
        let pk_bytes = pk.to_wire_bytes();
        let again =
            <$pk>::from_wire_bytes(&pk_bytes).expect(concat!($name, ": own public key parses"));
        assert_eq!(
            again.to_wire_bytes(),
            pk_bytes,
            concat!($name, ": public key re-encodes")
        );
        let (ct, shared) = <$scheme>::encaps(pk, &mut $rng);
        assert_eq!(
            <$scheme>::decaps(sk, &ct).to_wire_bytes(),
            shared.to_wire_bytes(),
            concat!($name, ": honest ciphertext")
        );
        let ct_bytes = ct.to_wire_bytes();
        let again =
            <$ct>::from_wire_bytes(&ct_bytes).expect(concat!($name, ": own ciphertext parses"));
        assert_eq!(
            again.to_wire_bytes(),
            ct_bytes,
            concat!($name, ": ciphertext re-encodes")
        );
        let bad = <$ct>::from_wire_bytes(&flipped(&ct_bytes, $at, $bit))
            .expect(concat!($name, ": a ciphertext of the right length parses"));
        assert_ne!(
            <$scheme>::decaps(sk, &bad).to_wire_bytes(),
            shared.to_wire_bytes(),
            concat!(
                $name,
                ": a flipped ciphertext decapsulated to the honest secret"
            )
        );
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 + SEED {
        return;
    }
    let set = data[0] % SETS;
    let at = usize::from(data[1]);
    let bit = data[2];
    let seed: [u8; SEED] = data[3..3 + SEED].try_into().expect("48 bytes");
    let msg = &data[3 + SEED..];
    let mut rng = CtrDrbgAes256::new(&seed);
    match set {
        0 => ees!(
            "ees401ep1",
            NtruEes401Ep1,
            NtruEes401Ep1PublicKey,
            NtruEes401Ep1PrivateKey,
            NtruEes401Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        1 => ees!(
            "ees443ep1",
            NtruEes443Ep1,
            NtruEes443Ep1PublicKey,
            NtruEes443Ep1PrivateKey,
            NtruEes443Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        2 => ees!(
            "ees449ep1",
            NtruEes449Ep1,
            NtruEes449Ep1PublicKey,
            NtruEes449Ep1PrivateKey,
            NtruEes449Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        3 => ees!(
            "ees541ep1",
            NtruEes541Ep1,
            NtruEes541Ep1PublicKey,
            NtruEes541Ep1PrivateKey,
            NtruEes541Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        4 => ees!(
            "ees677ep1",
            NtruEes677Ep1,
            NtruEes677Ep1PublicKey,
            NtruEes677Ep1PrivateKey,
            NtruEes677Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        5 => ees!(
            "ees1087ep1",
            NtruEes1087Ep1,
            NtruEes1087Ep1PublicKey,
            NtruEes1087Ep1PrivateKey,
            NtruEes1087Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        6 => ees!(
            "ees1087ep2",
            NtruEes1087Ep2,
            NtruEes1087Ep2PublicKey,
            NtruEes1087Ep2PrivateKey,
            NtruEes1087Ep2Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        7 => ees!(
            "ees1171ep1",
            NtruEes1171Ep1,
            NtruEes1171Ep1PublicKey,
            NtruEes1171Ep1PrivateKey,
            NtruEes1171Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        8 => ees!(
            "ees1499ep1",
            NtruEes1499Ep1,
            NtruEes1499Ep1PublicKey,
            NtruEes1499Ep1PrivateKey,
            NtruEes1499Ep1Ciphertext,
            rng,
            msg,
            at,
            bit
        ),
        9 => kem!(
            "ntruhps2048509",
            NtruHps509,
            NtruHps509PublicKey,
            NtruHps509PrivateKey,
            NtruHps509Ciphertext,
            rng,
            at,
            bit
        ),
        10 => kem!(
            "ntruhps2048677",
            NtruHps677,
            NtruHps677PublicKey,
            NtruHps677PrivateKey,
            NtruHps677Ciphertext,
            rng,
            at,
            bit
        ),
        11 => kem!(
            "ntruhps4096821",
            NtruHps821,
            NtruHps821PublicKey,
            NtruHps821PrivateKey,
            NtruHps821Ciphertext,
            rng,
            at,
            bit
        ),
        _ => kem!(
            "ntruhrss701",
            NtruHrss701,
            NtruHrss701PublicKey,
            NtruHrss701PrivateKey,
            NtruHrss701Ciphertext,
            rng,
            at,
            bit
        ),
    }
});
