//! MAC known answers.
//!
//! - RFC 4231, "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
//!   HMAC-SHA-384, and HMAC-SHA-512" (M. Nystrom, December 2005), section 4,
//!   Test Cases 1-7 for HMAC-SHA-224, HMAC-SHA-384 and HMAC-SHA-512. The
//!   HMAC-SHA-256 results are already pinned by the unit tests in
//!   `src/hash/hmac.rs`. Test Case 5 publishes only the leftmost 128 bits of
//!   each output, which `Hmac::verify` refuses (it compares full tags only);
//!   Test Cases 6 and 7 use a 131-byte key, longer than every block size, so
//!   the key is hashed first.
//! - NIST's "Examples with Intermediate Values" for SP 800-38B CMAC:
//!   AES_CMAC.pdf, Examples #1-#4 (messages of 0, 16, 20 and 64 bytes) for
//!   CMAC-AES192 and CMAC-AES256, and Examples #3 and #4 for CMAC-AES128,
//!   whose Examples #1 and #2 are already pinned by `src/modes/mod.rs`; and
//!   TDES_CMAC.pdf, Samples #1-#4 (messages of 0, 16, 20 and 32 bytes, 64-bit
//!   tags) for three-key TDEA and for two-key TDEA (Key3 = Key1). Each CMAC
//!   tag is also verified, and `verify` is shown to refuse the tag shortened,
//!   extended, emptied or altered: only the full block-length tag matches.

mod common;

use common::decode_hex;
use cryptography::{
    Aes128, Aes192, Aes256, BlockCipher, Cmac, Digest, Hmac, Sha224, Sha384, Sha512, TripleDes,
};

struct HmacCase {
    number: u32,
    key: &'static str,
    data: &'static str,
    sha224: &'static str,
    sha384: &'static str,
    sha512: &'static str,
}

const RFC4231: [HmacCase; 7] = [
    // RFC 4231 section 4.2, Test Case 1.
    HmacCase {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        sha224: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        sha384: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                faea9ea9076ede7f4af152e8b2fa9cb6",
        sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    // RFC 4231 section 4.3, Test Case 2.
    HmacCase {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        sha224: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
        sha384: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                8e2240ca5e69e2c78b3239ecfab21649",
        sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    // RFC 4231 section 4.4, Test Case 3.
    HmacCase {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
              dddddddddddddddddddddddddddddddddddd",
        sha224: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
        sha384: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                2a5ab39dc13814b94e3ab6e101a34f27",
        sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
    // RFC 4231 section 4.5, Test Case 4.
    HmacCase {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
              cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        sha224: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
        sha384: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                6801dd23c4a7d679ccf8a386c674cffb",
        sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
                a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    },
    // RFC 4231 section 4.6, Test Case 5.
    HmacCase {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        sha224: "0e2aea68a90c8d37c988bcdb9fca6fa8",
        sha384: "3abf34c3503b2a23a46efc619baef897",
        sha512: "415fad6271580a531d4179bc891d87a6",
    },
    // RFC 4231 section 4.7, Test Case 6.
    HmacCase {
        number: 6,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaa",
        data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
              65204b6579202d2048617368204b6579204669727374",
        sha224: "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
        sha384: "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                0c2ef6ab4030fe8296248df163f44952",
        sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
    // RFC 4231 section 4.8, Test Case 7.
    HmacCase {
        number: 7,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaa",
        data: "5468697320697320612074657374207573696e672061206c6172676572207468\
              616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
              68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
              647320746f20626520686173686564206265666f7265206265696e6720757365\
              642062792074686520484d414320616c676f726974686d2e",
        sha224: "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
        sha384: "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                a678cc31e799176d3860e6110c46523e",
        sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
                b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    },
];

fn check_hmac<H: Digest>(number: u32, expected: fn(&HmacCase) -> &'static str, label: &str) {
    let case = &RFC4231[usize::try_from(number - 1).expect("case index")];
    assert_eq!(case.number, number);
    let key = decode_hex(case.key);
    let data = decode_hex(case.data);
    let expected = decode_hex(expected(case));

    let tag = Hmac::<H>::compute(&key, &data);
    let mut mac = Hmac::<H>::new(&key);
    let (first, second) = data.split_at(data.len() / 3);
    mac.update(first);
    mac.update(second);
    let incremental = mac.finalize();
    assert_eq!(incremental, tag, "Test Case {number}, {label}: incremental");

    if number == 5 {
        // Section 4.6: "Test with a truncation of output to 128 bits." The
        // published value is a prefix of the tag; `verify` compares full
        // tags only, so it refuses the truncation and accepts the whole tag.
        assert_eq!(expected.len(), 16);
        assert_eq!(
            tag[..16],
            expected[..],
            "Test Case 5, {label}: leftmost 128 bits"
        );
        assert!(
            !Hmac::<H>::verify(&key, &data, &expected),
            "Test Case 5, {label}: verify refuses the 128-bit truncation"
        );
        assert!(
            Hmac::<H>::verify(&key, &data, &tag),
            "Test Case 5, {label}: verify accepts the full tag"
        );
    } else {
        assert_eq!(tag, expected, "Test Case {number}, {label}");
        assert!(
            Hmac::<H>::verify(&key, &data, &expected),
            "Test Case {number}, {label}: verify"
        );
    }
}

/// RFC 4231 Test Case 1, HMAC-SHA-224.
#[test]
fn rfc4231_case_1_hmac_sha224() {
    check_hmac::<Sha224>(1, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 1, HMAC-SHA-384.
#[test]
fn rfc4231_case_1_hmac_sha384() {
    check_hmac::<Sha384>(1, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 1, HMAC-SHA-512.
#[test]
fn rfc4231_case_1_hmac_sha512() {
    check_hmac::<Sha512>(1, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 2, HMAC-SHA-224.
#[test]
fn rfc4231_case_2_hmac_sha224() {
    check_hmac::<Sha224>(2, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 2, HMAC-SHA-384.
#[test]
fn rfc4231_case_2_hmac_sha384() {
    check_hmac::<Sha384>(2, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 2, HMAC-SHA-512.
#[test]
fn rfc4231_case_2_hmac_sha512() {
    check_hmac::<Sha512>(2, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 3, HMAC-SHA-224.
#[test]
fn rfc4231_case_3_hmac_sha224() {
    check_hmac::<Sha224>(3, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 3, HMAC-SHA-384.
#[test]
fn rfc4231_case_3_hmac_sha384() {
    check_hmac::<Sha384>(3, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 3, HMAC-SHA-512.
#[test]
fn rfc4231_case_3_hmac_sha512() {
    check_hmac::<Sha512>(3, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 4, HMAC-SHA-224.
#[test]
fn rfc4231_case_4_hmac_sha224() {
    check_hmac::<Sha224>(4, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 4, HMAC-SHA-384.
#[test]
fn rfc4231_case_4_hmac_sha384() {
    check_hmac::<Sha384>(4, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 4, HMAC-SHA-512.
#[test]
fn rfc4231_case_4_hmac_sha512() {
    check_hmac::<Sha512>(4, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 5, HMAC-SHA-224.
#[test]
fn rfc4231_case_5_hmac_sha224() {
    check_hmac::<Sha224>(5, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 5, HMAC-SHA-384.
#[test]
fn rfc4231_case_5_hmac_sha384() {
    check_hmac::<Sha384>(5, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 5, HMAC-SHA-512.
#[test]
fn rfc4231_case_5_hmac_sha512() {
    check_hmac::<Sha512>(5, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 6, HMAC-SHA-224.
#[test]
fn rfc4231_case_6_hmac_sha224() {
    check_hmac::<Sha224>(6, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 6, HMAC-SHA-384.
#[test]
fn rfc4231_case_6_hmac_sha384() {
    check_hmac::<Sha384>(6, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 6, HMAC-SHA-512.
#[test]
fn rfc4231_case_6_hmac_sha512() {
    check_hmac::<Sha512>(6, |c| c.sha512, "HMAC-SHA-512");
}

/// RFC 4231 Test Case 7, HMAC-SHA-224.
#[test]
fn rfc4231_case_7_hmac_sha224() {
    check_hmac::<Sha224>(7, |c| c.sha224, "HMAC-SHA-224");
}

/// RFC 4231 Test Case 7, HMAC-SHA-384.
#[test]
fn rfc4231_case_7_hmac_sha384() {
    check_hmac::<Sha384>(7, |c| c.sha384, "HMAC-SHA-384");
}

/// RFC 4231 Test Case 7, HMAC-SHA-512.
#[test]
fn rfc4231_case_7_hmac_sha512() {
    check_hmac::<Sha512>(7, |c| c.sha512, "HMAC-SHA-512");
}

fn check_cmac<C: BlockCipher>(mac: &Cmac<C>, message: &str, tag: &str, label: &str) {
    let message = decode_hex(message);
    let tag = decode_hex(tag);
    assert_eq!(mac.compute(&message), tag, "{label}");
    assert!(mac.verify(&message, &tag), "{label}: verify");

    // `verify` takes only the full block-length tag: a truncated tag is not a
    // prefix match, an extended one is not a match, and a flipped byte fails.
    assert!(
        !mac.verify(&message, &tag[..tag.len() - 1]),
        "{label}: short tag"
    );
    assert!(
        !mac.verify(&message, &tag[..tag.len() / 2]),
        "{label}: half tag"
    );
    assert!(!mac.verify(&message, &[]), "{label}: empty tag");
    let mut extended = tag.clone();
    extended.push(0x00);
    assert!(!mac.verify(&message, &extended), "{label}: long tag");
    let mut flipped = tag.clone();
    flipped[0] ^= 0x01;
    assert!(!mac.verify(&message, &flipped), "{label}: flipped tag");
}

/// AES_CMAC.pdf, CMAC-AES128 key.
const CMAC_AES128_KEY: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
/// AES_CMAC.pdf, CMAC-AES192 key.
const CMAC_AES192_KEY: &str = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B";
/// AES_CMAC.pdf, CMAC-AES256 key.
const CMAC_AES256_KEY: &str = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";

/// AES_CMAC.pdf, CMAC-AES128, Example #3 (Mlen = 20).
#[test]
fn cmac_aes128_example_3() {
    let key = decode_hex(CMAC_AES128_KEY);
    let mac = Cmac::new(Aes128::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
        "7D85449EA6EA19C823A7BF78837DFADE",
        "CMAC-AES128 Example #3",
    );
}

/// AES_CMAC.pdf, CMAC-AES128, Example #4 (Mlen = 64).
#[test]
fn cmac_aes128_example_4() {
    let key = decode_hex(CMAC_AES128_KEY);
    let mac = Cmac::new(Aes128::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
        30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        "51F0BEBF7E3B9D92FC49741779363CFE",
        "CMAC-AES128 Example #4",
    );
}

/// AES_CMAC.pdf, CMAC-AES192, Example #1 (Mlen = 0).
#[test]
fn cmac_aes192_example_1() {
    let key = decode_hex(CMAC_AES192_KEY);
    let mac = Cmac::new(Aes192::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "",
        "D17DDF46ADAACDE531CAC483DE7A9367",
        "CMAC-AES192 Example #1",
    );
}

/// AES_CMAC.pdf, CMAC-AES192, Example #2 (Mlen = 16).
#[test]
fn cmac_aes192_example_2() {
    let key = decode_hex(CMAC_AES192_KEY);
    let mac = Cmac::new(Aes192::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172A",
        "9E99A7BF31E710900662F65E617C5184",
        "CMAC-AES192 Example #2",
    );
}

/// AES_CMAC.pdf, CMAC-AES192, Example #3 (Mlen = 20).
#[test]
fn cmac_aes192_example_3() {
    let key = decode_hex(CMAC_AES192_KEY);
    let mac = Cmac::new(Aes192::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
        "3D75C194ED96070444A9FA7EC740ECF8",
        "CMAC-AES192 Example #3",
    );
}

/// AES_CMAC.pdf, CMAC-AES192, Example #4 (Mlen = 64).
#[test]
fn cmac_aes192_example_4() {
    let key = decode_hex(CMAC_AES192_KEY);
    let mac = Cmac::new(Aes192::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
        30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        "A1D5DF0EED790F794D77589659F39A11",
        "CMAC-AES192 Example #4",
    );
}

/// AES_CMAC.pdf, CMAC-AES256, Example #1 (Mlen = 0).
#[test]
fn cmac_aes256_example_1() {
    let key = decode_hex(CMAC_AES256_KEY);
    let mac = Cmac::new(Aes256::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "",
        "028962F61B7BF89EFC6B551F4667D983",
        "CMAC-AES256 Example #1",
    );
}

/// AES_CMAC.pdf, CMAC-AES256, Example #2 (Mlen = 16).
#[test]
fn cmac_aes256_example_2() {
    let key = decode_hex(CMAC_AES256_KEY);
    let mac = Cmac::new(Aes256::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172A",
        "28A7023F452E8F82BD4BF28D8C37C35C",
        "CMAC-AES256 Example #2",
    );
}

/// AES_CMAC.pdf, CMAC-AES256, Example #3 (Mlen = 20).
#[test]
fn cmac_aes256_example_3() {
    let key = decode_hex(CMAC_AES256_KEY);
    let mac = Cmac::new(Aes256::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
        "156727DC0878944A023C1FE03BAD6D93",
        "CMAC-AES256 Example #3",
    );
}

/// AES_CMAC.pdf, CMAC-AES256, Example #4 (Mlen = 64).
#[test]
fn cmac_aes256_example_4() {
    let key = decode_hex(CMAC_AES256_KEY);
    let mac = Cmac::new(Aes256::new(&key.try_into().expect("AES key")));
    check_cmac(
        &mac,
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
        30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        "E1992190549F6ED5696A2C056C315410",
        "CMAC-AES256 Example #4",
    );
}

/// TDES_CMAC.pdf, first CMAC-TDES block: Key1 || Key2 || Key3.
const CMAC_TDEA_3KEY: &str = "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123";
/// TDES_CMAC.pdf, second CMAC-TDES block: Key1 || Key2 (its Key3 equals Key1).
const CMAC_TDEA_2KEY: &str = "0123456789ABCDEF23456789ABCDEF01";

/// TDES_CMAC.pdf, 3-key TDEA, Sample #1 (0-byte message).
#[test]
fn cmac_tdea_3key_sample_1() {
    let key = decode_hex(CMAC_TDEA_3KEY);
    let cipher =
        TripleDes::new_3key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "",
        "7DB0D37DF936C550",
        "TDEA 3key Sample #1",
    );
}

/// TDES_CMAC.pdf, 3-key TDEA, Sample #2 (16-byte message).
#[test]
fn cmac_tdea_3key_sample_2() {
    let key = decode_hex(CMAC_TDEA_3KEY);
    let cipher =
        TripleDes::new_3key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172A",
        "30239CF1F52E6609",
        "TDEA 3key Sample #2",
    );
}

/// TDES_CMAC.pdf, 3-key TDEA, Sample #3 (20-byte message).
#[test]
fn cmac_tdea_3key_sample_3() {
    let key = decode_hex(CMAC_TDEA_3KEY);
    let cipher =
        TripleDes::new_3key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
        "6C9F3EE4923F6BE2",
        "TDEA 3key Sample #3",
    );
}

/// TDES_CMAC.pdf, 3-key TDEA, Sample #4 (32-byte message).
#[test]
fn cmac_tdea_3key_sample_4() {
    let key = decode_hex(CMAC_TDEA_3KEY);
    let cipher =
        TripleDes::new_3key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51",
        "99429BD0BF7904E5",
        "TDEA 3key Sample #4",
    );
}

/// TDES_CMAC.pdf, 2-key TDEA, Sample #1 (0-byte message).
#[test]
fn cmac_tdea_2key_sample_1() {
    let key = decode_hex(CMAC_TDEA_2KEY);
    let cipher =
        TripleDes::new_2key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "",
        "79CE52A7F786A960",
        "TDEA 2key Sample #1",
    );
}

/// TDES_CMAC.pdf, 2-key TDEA, Sample #2 (16-byte message).
#[test]
fn cmac_tdea_2key_sample_2() {
    let key = decode_hex(CMAC_TDEA_2KEY);
    let cipher =
        TripleDes::new_2key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172A",
        "CC18A0B79AF2413B",
        "TDEA 2key Sample #2",
    );
}

/// TDES_CMAC.pdf, 2-key TDEA, Sample #3 (20-byte message).
#[test]
fn cmac_tdea_2key_sample_3() {
    let key = decode_hex(CMAC_TDEA_2KEY);
    let cipher =
        TripleDes::new_2key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
        "C06D377ECD101969",
        "TDEA 2key Sample #3",
    );
}

/// TDES_CMAC.pdf, 2-key TDEA, Sample #4 (32-byte message).
#[test]
fn cmac_tdea_2key_sample_4() {
    let key = decode_hex(CMAC_TDEA_2KEY);
    let cipher =
        TripleDes::new_2key(&key.try_into().expect("TDEA key")).expect("NIST key is accepted");
    check_cmac(
        &Cmac::new(cipher),
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51",
        "9CD33580F9B64DFB",
        "TDEA 2key Sample #4",
    );
}
