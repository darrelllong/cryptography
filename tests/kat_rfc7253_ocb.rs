//! RFC 7253, "The OCB Authenticated-Encryption Algorithm" (T. Krovetz,
//! P. Rogaway, May 2014), Appendix A "Sample Results", for every AES
//! parameter set of section 3.1.
//!
//! The values are transcribed from the RFC as published at
//! <https://www.rfc-editor.org/rfc/rfc7253.txt>; line numbers below are lines
//! of that file (Appendix A runs from line 791, pages 15 to 18).
//!
//! - The sixteen (N, A, P, C) samples under K = 000102030405060708090A0B0C0D0E0F
//!   with a 128-bit tag (lines 798-924). Samples 1, 2 and 4 are already pinned
//!   by the unit tests in `src/modes/ocb.rs`; the other thirteen, including
//!   every sample whose A or P spans more than one block (24, 32 and 40
//!   bytes), are pinned here.
//! - The sample with a 96-bit tag under K = 0F0E0D0C0B0A09080706050403020100
//!   (lines 959-971).
//! - The iterative test that encrypts every length from 0 to 127 bytes (lines
//!   973-993), against its outputs for all nine parameter sets
//!   AEAD_AES_{128,192,256}_OCB_TAGLEN{128,96,64} (lines 996-1004).
//!
//! Every sample is also decrypted, and must be refused once its last tag byte
//! is flipped.

mod common;

use common::decode_hex;
use cryptography::{Aes128, Aes192, Aes256, BlockCipher, Ocb};

/// RFC 7253 Appendix A: the key of the sixteen samples.
const KEY: &str = "000102030405060708090A0B0C0D0E0F";

struct Sample {
    number: u32,
    nonce: &'static str,
    aad: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
}

const SAMPLES: [Sample; 13] = [
    // RFC 7253 Appendix A, sample 3 of 16: 8-byte A, 0-byte P.
    Sample {
        number: 3,
        nonce: "BBAA99887766554433221102",
        aad: "0001020304050607",
        plaintext: "",
        ciphertext: "81017F8203F081277152FADE694A0A00",
    },
    // RFC 7253 Appendix A, sample 5 of 16: 16-byte A, 16-byte P.
    Sample {
        number: 5,
        nonce: "BBAA99887766554433221104",
        aad: "000102030405060708090A0B0C0D0E0F",
        plaintext: "000102030405060708090A0B0C0D0E0F",
        ciphertext: "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358",
    },
    // RFC 7253 Appendix A, sample 6 of 16: 16-byte A, 0-byte P.
    Sample {
        number: 6,
        nonce: "BBAA99887766554433221105",
        aad: "000102030405060708090A0B0C0D0E0F",
        plaintext: "",
        ciphertext: "8CF761B6902EF764462AD86498CA6B97",
    },
    // RFC 7253 Appendix A, sample 7 of 16: 0-byte A, 16-byte P.
    Sample {
        number: 7,
        nonce: "BBAA99887766554433221106",
        aad: "",
        plaintext: "000102030405060708090A0B0C0D0E0F",
        ciphertext: "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D",
    },
    // RFC 7253 Appendix A, sample 8 of 16: 24-byte A, 24-byte P.
    Sample {
        number: 8,
        nonce: "BBAA99887766554433221107",
        aad: "000102030405060708090A0B0C0D0E0F1011121314151617",
        plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
        ciphertext: "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F573\
                    56D7F3C90BB0E07F",
    },
    // RFC 7253 Appendix A, sample 9 of 16: 24-byte A, 0-byte P.
    Sample {
        number: 9,
        nonce: "BBAA99887766554433221108",
        aad: "000102030405060708090A0B0C0D0E0F1011121314151617",
        plaintext: "",
        ciphertext: "6DC225A071FC1B9F7C69F93B0F1E10DE",
    },
    // RFC 7253 Appendix A, sample 10 of 16: 0-byte A, 24-byte P.
    Sample {
        number: 10,
        nonce: "BBAA99887766554433221109",
        aad: "",
        plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
        ciphertext: "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914\
                    D85C0B1EB38357FF",
    },
    // RFC 7253 Appendix A, sample 11 of 16: 32-byte A, 32-byte P.
    Sample {
        number: 11,
        nonce: "BBAA9988776655443322110A",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext: "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A485\
                    40FBBA186C5553C68AD9F592A79A4240",
    },
    // RFC 7253 Appendix A, sample 12 of 16: 32-byte A, 0-byte P.
    Sample {
        number: 12,
        nonce: "BBAA9988776655443322110B",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        plaintext: "",
        ciphertext: "FE80690BEE8A485D11F32965BC9D2A32",
    },
    // RFC 7253 Appendix A, sample 13 of 16: 0-byte A, 32-byte P.
    Sample {
        number: 13,
        nonce: "BBAA9988776655443322110C",
        aad: "",
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ciphertext: "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDF\
                    B5E1DDE3BC18A5F840B52E653444D5DF",
    },
    // RFC 7253 Appendix A, sample 14 of 16: 40-byte A, 40-byte P.
    Sample {
        number: 14,
        nonce: "BBAA9988776655443322110D",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
             2021222324252627",
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
                   2021222324252627",
        ciphertext: "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B\
                    65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60",
    },
    // RFC 7253 Appendix A, sample 15 of 16: 40-byte A, 0-byte P.
    Sample {
        number: 15,
        nonce: "BBAA9988776655443322110E",
        aad: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
             2021222324252627",
        plaintext: "",
        ciphertext: "C5CD9D1850C141E358649994EE701B68",
    },
    // RFC 7253 Appendix A, sample 16 of 16: 0-byte A, 40-byte P.
    Sample {
        number: 16,
        nonce: "BBAA9988776655443322110F",
        aad: "",
        plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
                   2021222324252627",
        ciphertext: "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5\
                    CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479",
    },
];

/// `OCB-ENCRYPT(K, N, A, P)`: the ciphertext followed by the tag.
fn seal<C: BlockCipher, const TAG_LEN: usize>(
    ocb: &Ocb<C, TAG_LEN>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    let tag = ocb.encrypt(nonce, aad, &mut data);
    data.extend_from_slice(&tag);
    data
}

/// `OCB-DECRYPT(K, N, A, C)` returns `plaintext`, and returns INVALID once the
/// last byte of the `TAG_LEN`-byte tag is flipped, leaving the buffer as it was.
fn check_open<C: BlockCipher, const TAG_LEN: usize>(
    label: &str,
    ocb: &Ocb<C, TAG_LEN>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &[u8],
) {
    let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let mut tag: [u8; TAG_LEN] = tag.try_into().expect("TAGLEN-bit tag");
    let mut data = body.to_vec();
    assert!(
        ocb.decrypt(nonce, aad, &mut data, &tag),
        "{label}: decrypt rejected"
    );
    assert_eq!(data, plaintext, "{label}: decrypted P");

    tag[TAG_LEN - 1] ^= 0x01;
    let mut data = body.to_vec();
    assert!(
        !ocb.decrypt(nonce, aad, &mut data, &tag),
        "{label}: altered tag accepted"
    );
    assert_eq!(data, body, "{label}: buffer changed on rejection");
}

fn check_sample(number: u32) {
    let sample = SAMPLES
        .iter()
        .find(|s| s.number == number)
        .expect("sample in table");
    let ocb = Ocb::<_, 16>::new(Aes128::new(
        &decode_hex(KEY).try_into().expect("128-bit key"),
    ));
    let nonce = decode_hex(sample.nonce);
    let aad = decode_hex(sample.aad);
    let plaintext = decode_hex(sample.plaintext);
    let ciphertext = decode_hex(sample.ciphertext);
    assert_eq!(
        seal(&ocb, &nonce, &aad, &plaintext),
        ciphertext,
        "sample {number}: C"
    );
    check_open(
        &format!("sample {number}"),
        &ocb,
        &nonce,
        &aad,
        &plaintext,
        &ciphertext,
    );
}

/// RFC 7253 Appendix A, sample 3: 8-byte A, 0-byte P.
#[test]
fn sample_03() {
    check_sample(3);
}

/// RFC 7253 Appendix A, sample 5: 16-byte A, 16-byte P.
#[test]
fn sample_05() {
    check_sample(5);
}

/// RFC 7253 Appendix A, sample 6: 16-byte A, 0-byte P.
#[test]
fn sample_06() {
    check_sample(6);
}

/// RFC 7253 Appendix A, sample 7: 0-byte A, 16-byte P.
#[test]
fn sample_07() {
    check_sample(7);
}

/// RFC 7253 Appendix A, sample 8: 24-byte A, 24-byte P.
#[test]
fn sample_08() {
    check_sample(8);
}

/// RFC 7253 Appendix A, sample 9: 24-byte A, 0-byte P.
#[test]
fn sample_09() {
    check_sample(9);
}

/// RFC 7253 Appendix A, sample 10: 0-byte A, 24-byte P.
#[test]
fn sample_10() {
    check_sample(10);
}

/// RFC 7253 Appendix A, sample 11: 32-byte A, 32-byte P.
#[test]
fn sample_11() {
    check_sample(11);
}

/// RFC 7253 Appendix A, sample 12: 32-byte A, 0-byte P.
#[test]
fn sample_12() {
    check_sample(12);
}

/// RFC 7253 Appendix A, sample 13: 0-byte A, 32-byte P.
#[test]
fn sample_13() {
    check_sample(13);
}

/// RFC 7253 Appendix A, sample 14: 40-byte A, 40-byte P.
#[test]
fn sample_14() {
    check_sample(14);
}

/// RFC 7253 Appendix A, sample 15: 40-byte A, 0-byte P.
#[test]
fn sample_15() {
    check_sample(15);
}

/// RFC 7253 Appendix A, sample 16: 0-byte A, 40-byte P.
#[test]
fn sample_16() {
    check_sample(16);
}

/// RFC 7253 Appendix A, lines 959-971: "a result with a tag length of 96 bits
/// and a different key" (AEAD_AES_128_OCB_TAGLEN96), with 40-byte A and P.
#[test]
fn sample_taglen_96() {
    let key = decode_hex("0F0E0D0C0B0A09080706050403020100");
    let nonce = decode_hex("BBAA9988776655443322110D");
    let aad = decode_hex(
        "000102030405060708090A0B0C0D0E0F1011121314151617\
                   18191A1B1C1D1E1F2021222324252627",
    );
    let plaintext = decode_hex(
        "000102030405060708090A0B0C0D0E0F1011121314151617\
                         18191A1B1C1D1E1F2021222324252627",
    );
    let ciphertext = decode_hex(
        "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1\
                          A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FD\
                          AC4F02AA",
    );
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + 12,
        "C is TAGLEN = 96 bits longer than P"
    );

    let key: [u8; 16] = key.try_into().expect("128-bit key");
    let ocb = Ocb::<_, 12>::new(Aes128::new(&key));
    assert_eq!(
        seal(&ocb, &nonce, &aad, &plaintext),
        ciphertext,
        "TAGLEN 96 sample: C"
    );
    check_open(
        "TAGLEN 96 sample",
        &ocb,
        &nonce,
        &aad,
        &plaintext,
        &ciphertext,
    );

    // Section 4.2 folds TAGLEN into the nonce block, so the same inputs under
    // a 128-bit tag differ in the ciphertext body, not only in the tag.
    let taglen128 = Ocb::<_, 16>::new(Aes128::new(&key));
    let body = &ciphertext[..plaintext.len()];
    assert_ne!(
        &seal(&taglen128, &nonce, &aad, &plaintext)[..plaintext.len()],
        body
    );
}

// RFC 7253 Appendix A, lines 996-1004: outputs of the iterative test.
const AES_128_TAGLEN128_OUTPUT: &str = "67E944D23256C5E0B6C61FA22FDF1EA2";
const AES_192_TAGLEN128_OUTPUT: &str = "F673F2C3E7174AAE7BAE986CA9F29E17";
const AES_256_TAGLEN128_OUTPUT: &str = "D90EB8E9C977C88B79DD793D7FFA161C";
const AES_128_TAGLEN96_OUTPUT: &str = "77A3D8E73589158D25D01209";
const AES_192_TAGLEN96_OUTPUT: &str = "05D56EAD2752C86BE6932C5E";
const AES_256_TAGLEN96_OUTPUT: &str = "5458359AC23B0CBA9E6330DD";
const AES_128_TAGLEN64_OUTPUT: &str = "192C9B7BD90BA06A";
const AES_192_TAGLEN64_OUTPUT: &str = "0066BC6E0EF34E24";
const AES_256_TAGLEN64_OUTPUT: &str = "7D4EA5D445501CBE";

/// `num2str(value, 96)`: `value` as a 96-bit big-endian string.
fn nonce96(value: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&value.to_be_bytes());
    out
}

/// `K = zeros(KEYLEN-8) || num2str(TAGLEN,8)` (line 976).
fn iterative_key<const KEY_LEN: usize, const TAG_LEN: usize>() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[KEY_LEN - 1] = u8::try_from(TAG_LEN * 8).expect("TAGLEN fits in 8 bits");
    key
}

/// The length of C after the loop. Lines 990-993: "Iteration i of the loop
/// adds 2i + (3 * TAGLEN / 8) bytes to C, resulting in an ultimate length for
/// C of 22,400 bytes when TAGLEN == 128, 20,864 bytes when TAGLEN == 192, and
/// 19,328 bytes when TAGLEN == 64." TAGLEN is at most 128 (section 3), and
/// 20,864 is what that sum gives for TAGLEN 96, the remaining parameter set.
fn iterative_c_len<const TAG_LEN: usize>() -> usize {
    let summed: usize = (0..128).map(|i| 2 * i + 3 * TAG_LEN).sum();
    let stated = match TAG_LEN * 8 {
        128 => 22_400,
        96 => 20_864,
        64 => 19_328,
        taglen => panic!("RFC 7253 states no length of C for TAGLEN {taglen}"),
    };
    assert_eq!(
        summed, stated,
        "lines 990-993 disagree for TAG_LEN {TAG_LEN}"
    );
    stated
}

/// The RFC 7253 Appendix A iterative test, verbatim (lines 976-988):
///
/// ```text
/// K = zeros(KEYLEN-8) || num2str(TAGLEN,8)
/// C = <empty string>
/// for i = 0 to 127 do
///    S = zeros(8i)
///    N = num2str(3i+1,96)
///    C = C || OCB-ENCRYPT(K,N,S,S)
///    N = num2str(3i+2,96)
///    C = C || OCB-ENCRYPT(K,N,<empty string>,S)
///    N = num2str(3i+3,96)
///    C = C || OCB-ENCRYPT(K,N,S,<empty string>)
/// end for
/// N = num2str(385,96)
/// Output : OCB-ENCRYPT(K,N,C,<empty string>)
/// ```
fn iterative_output<C: BlockCipher, const TAG_LEN: usize>(cipher: C) -> Vec<u8> {
    let ocb = Ocb::<C, TAG_LEN>::new(cipher);
    let mut c = Vec::new();
    for i in 0..128u64 {
        let s = vec![0u8; usize::try_from(i).expect("small length")];
        c.extend_from_slice(&seal(&ocb, &nonce96(3 * i + 1), &s, &s));
        c.extend_from_slice(&seal(&ocb, &nonce96(3 * i + 2), &[], &s));
        c.extend_from_slice(&seal(&ocb, &nonce96(3 * i + 3), &s, &[]));
    }
    assert_eq!(c.len(), iterative_c_len::<TAG_LEN>(), "length of C");
    seal(&ocb, &nonce96(385), &c, &[])
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_128_OCB_TAGLEN128 (line 996).
#[test]
fn iterative_aes_128_taglen_128() {
    let output = iterative_output::<_, 16>(Aes128::new(&iterative_key::<16, 16>()));
    assert_eq!(output, decode_hex(AES_128_TAGLEN128_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_192_OCB_TAGLEN128 (line 997).
#[test]
fn iterative_aes_192_taglen_128() {
    let output = iterative_output::<_, 16>(Aes192::new(&iterative_key::<24, 16>()));
    assert_eq!(output, decode_hex(AES_192_TAGLEN128_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_256_OCB_TAGLEN128 (line 998).
#[test]
fn iterative_aes_256_taglen_128() {
    let output = iterative_output::<_, 16>(Aes256::new(&iterative_key::<32, 16>()));
    assert_eq!(output, decode_hex(AES_256_TAGLEN128_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_128_OCB_TAGLEN96 (line 999).
#[test]
fn iterative_aes_128_taglen_96() {
    let output = iterative_output::<_, 12>(Aes128::new(&iterative_key::<16, 12>()));
    assert_eq!(output, decode_hex(AES_128_TAGLEN96_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_192_OCB_TAGLEN96 (line 1000).
#[test]
fn iterative_aes_192_taglen_96() {
    let output = iterative_output::<_, 12>(Aes192::new(&iterative_key::<24, 12>()));
    assert_eq!(output, decode_hex(AES_192_TAGLEN96_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_256_OCB_TAGLEN96 (line 1001).
#[test]
fn iterative_aes_256_taglen_96() {
    let output = iterative_output::<_, 12>(Aes256::new(&iterative_key::<32, 12>()));
    assert_eq!(output, decode_hex(AES_256_TAGLEN96_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_128_OCB_TAGLEN64 (line 1002).
#[test]
fn iterative_aes_128_taglen_64() {
    let output = iterative_output::<_, 8>(Aes128::new(&iterative_key::<16, 8>()));
    assert_eq!(output, decode_hex(AES_128_TAGLEN64_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_192_OCB_TAGLEN64 (line 1003).
#[test]
fn iterative_aes_192_taglen_64() {
    let output = iterative_output::<_, 8>(Aes192::new(&iterative_key::<24, 8>()));
    assert_eq!(output, decode_hex(AES_192_TAGLEN64_OUTPUT));
}

/// RFC 7253 Appendix A iterative test, AEAD_AES_256_OCB_TAGLEN64 (line 1004).
#[test]
fn iterative_aes_256_taglen_64() {
    let output = iterative_output::<_, 8>(Aes256::new(&iterative_key::<32, 8>()));
    assert_eq!(output, decode_hex(AES_256_TAGLEN64_OUTPUT));
}
