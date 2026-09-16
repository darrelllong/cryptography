//! XChaCha20 known answers from draft-irtf-cfrg-xchacha-03, "XChaCha:
//! eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305" (S. Arciszewski,
//! January 2020), Appendix A.3 "Developer-Friendly Test Vectors".
//!
//! - A.3.2.1 and A.3.2.2: the XChaCha20 keystream and ciphertext of a 304-byte
//!   plaintext at initial block counters 0 and 1.
//! - A.3.1: AEAD_XChaCha20_Poly1305. The crate has no XChaCha20-Poly1305 type,
//!   so this vector is checked by composing the construction the draft
//!   defines (HChaCha20 subkey and 4 zero bytes || the last 8 nonce bytes fed
//!   to the RFC 8439 AEAD) from the public `XChaCha20` and `Poly1305`
//!   primitives. It pins the Poly1305 key, ciphertext and tag the draft prints.
//!
//! The unit tests in `src/ciphers/chacha20.rs` pin HChaCha20 (draft section
//! 2.2.1) and that XChaCha20 equals HChaCha20 followed by ChaCha20, but no
//! published XChaCha20 output.

mod common;

use common::{decode_hex, decode_hex_array};
use cryptography::{Poly1305, XChaCha20};

// draft-irtf-cfrg-xchacha-03 Appendix A.3.2 (A.3.2.1 and A.3.2.2 share the
// plaintext, key and IV).
const A32_PLAINTEXT: &str = "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973\
    20616c736f206b6e6f776e2061732074686520417369617469632077696c6420\
    646f672c2072656420646f672c20616e642077686973746c696e6720646f672e\
    2049742069732061626f7574207468652073697a65206f662061204765726d61\
    6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061\
    206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c\
    757369766520616e6420736b696c6c6564206a756d70657220697320636c6173\
    736966696564207769746820776f6c7665732c20636f796f7465732c206a6163\
    6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963\
    2066616d696c792043616e696461652e";
const A32_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const A32_IV: &str = "404142434445464748494a4b4c4d4e4f5051525354555658";

// Appendix A.3.2.1, "Block Counter = 0".
const A321_KEYSTREAM: &str = "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a\
    adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d\
    29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4\
    cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25\
    5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221\
    5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60\
    7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd\
    241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f\
    a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00\
    b3df507ca8c924f7017b7e712d15a2eb";
const A321_CIPHERTEXT: &str = "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9\
    8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d\
    4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da\
    ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744\
    3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240\
    7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c\
    09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae\
    577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c\
    cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663\
    93b93111c1a55dd7421a10184974c7c5";

// Appendix A.3.2.2, "Block Counter = 1".
const A322_KEYSTREAM: &str = "29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4\
    cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25\
    5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221\
    5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60\
    7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd\
    241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f\
    a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00\
    b3df507ca8c924f7017b7e712d15a2eb5c50484451e54e1b4b995bd8fdd94597\
    bb94d7af0b2c04df10ba0890899ed9293a0f55b8bafa999264035f1d4fbe7fe0\
    aafa109a62372027e50e10cdfecca127";
const A322_CIPHERTEXT: &str = "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87\
    ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05\
    3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f\
    7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201\
    12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc\
    047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63\
    d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73\
    c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4\
    d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683\
    8a9c71f70b5b5907a66f7ea49aadc409";

fn check_stream(counter: u32, keystream: &str, ciphertext: &str) {
    let key: [u8; 32] = decode_hex_array(A32_KEY);
    let iv: [u8; 24] = decode_hex_array(A32_IV);
    let plaintext = decode_hex(A32_PLAINTEXT);

    let mut stream = vec![0u8; plaintext.len()];
    XChaCha20::with_counter(&key, &iv, counter).fill(&mut stream);
    assert_eq!(
        stream,
        decode_hex(keystream),
        "keystream at counter {counter}"
    );

    let mut data = plaintext.clone();
    XChaCha20::with_counter(&key, &iv, counter).apply_keystream(&mut data);
    assert_eq!(
        data,
        decode_hex(ciphertext),
        "ciphertext at counter {counter}"
    );
    XChaCha20::with_counter(&key, &iv, counter).apply_keystream(&mut data);
    assert_eq!(data, plaintext, "decryption at counter {counter}");
}

/// draft-irtf-cfrg-xchacha-03 Appendix A.3.2.1: block counter 0.
#[test]
fn a3_2_1_xchacha20_counter_0() {
    check_stream(0, A321_KEYSTREAM, A321_CIPHERTEXT);
}

/// draft-irtf-cfrg-xchacha-03 Appendix A.3.2.2: block counter 1.
#[test]
fn a3_2_2_xchacha20_counter_1() {
    check_stream(1, A322_KEYSTREAM, A322_CIPHERTEXT);
}

// draft-irtf-cfrg-xchacha-03 Appendix A.3.1, AEAD_XCHACHA20_POLY1305.
const A31_PLAINTEXT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
    73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
    6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
    637265656e20776f756c642062652069742e";
const A31_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const A31_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const A31_IV: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
const A31_POLY1305_KEY: &str = "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5";
const A31_CIPHERTEXT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
    731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
    2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
    21f9664c97637da9768812f615c68b13b52e";
const A31_TAG: &str = "c0875924c1c7987947deafd8780acf49";

/// Zero bytes that pad `len` bytes to a multiple of 16 (RFC 8439 section 2.8).
fn pad16(len: usize) -> Vec<u8> {
    vec![0u8; (16 - len % 16) % 16]
}

/// draft-irtf-cfrg-xchacha-03 Appendix A.3.1, composed from `XChaCha20` and
/// `Poly1305`: block 0 gives the one-time key, blocks from 1 encrypt, and the
/// tag covers AAD || pad || ciphertext || pad || le64(|AAD|) || le64(|C|).
#[test]
fn a3_1_aead_xchacha20_poly1305_composed() {
    let key: [u8; 32] = decode_hex_array(A31_KEY);
    let iv: [u8; 24] = decode_hex_array(A31_IV);
    let aad = decode_hex(A31_AAD);
    let plaintext = decode_hex(A31_PLAINTEXT);

    let block0 = XChaCha20::with_counter(&key, &iv, 0).keystream_block();
    let poly_key: [u8; 32] = decode_hex_array(A31_POLY1305_KEY);
    assert_eq!(block0[..32], poly_key, "Poly1305 key");

    let mut ciphertext = plaintext.clone();
    XChaCha20::with_counter(&key, &iv, 1).apply_keystream(&mut ciphertext);
    assert_eq!(ciphertext, decode_hex(A31_CIPHERTEXT), "ciphertext");

    let mut mac_data = aad.clone();
    mac_data.extend_from_slice(&pad16(aad.len()));
    mac_data.extend_from_slice(&ciphertext);
    mac_data.extend_from_slice(&pad16(ciphertext.len()));
    mac_data.extend_from_slice(&u64::try_from(aad.len()).expect("fits").to_le_bytes());
    mac_data.extend_from_slice(&u64::try_from(ciphertext.len()).expect("fits").to_le_bytes());
    let tag: [u8; 16] = decode_hex_array(A31_TAG);
    assert_eq!(Poly1305::new(&poly_key).compute(&mac_data), tag, "tag");
}
