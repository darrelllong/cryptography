//! Hash known answers from the standards' published examples.
//!
//! - FIPS 180-4 (SHA-1, SHA-2), from NIST's "Examples with Intermediate
//!   Values" (SHA1.pdf, SHA224.pdf, SHA256.pdf, SHA384.pdf, SHA512.pdf,
//!   SHA512_224.pdf, SHA512_256.pdf), each document's "Two Block Message
//!   Sample": the 448-bit message for SHA-1, SHA-224 and SHA-256, and the
//!   896-bit message for SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
//!   The one-block "abc" samples are already pinned by the unit tests in
//!   `src/hash/sha1.rs` and `src/hash/sha2.rs`.
//! - FIPS 180-2 with Change Notice 1 (February 2004): the "Long Message"
//!   examples, one million repetitions of "a", in Appendices A.3 (SHA-1), B.3
//!   (SHA-256), C.3 (SHA-512) and D.3 (SHA-384) and the change notice's
//!   "SHA-224 Example (Long Message)". NIST publishes no such example for
//!   SHA-512/224 or SHA-512/256.
//! - RFC 1321 (MD5), Appendix A.5 "Test suite": the four entries the unit
//!   tests in `src/hash/md5.rs` do not already pin (they pin "", "abc" and
//!   "message digest").
//! - H. Dobbertin, A. Bosselaers, B. Preneel, "RIPEMD-160: A Strengthened
//!   Version of RIPEMD", Appendix B "Test Values": the six RIPEMD-160 entries
//!   the unit tests in `src/hash/ripemd160.rs` do not already pin (the same
//!   three as for MD5), including 8 times "1234567890" and one million "a".
//! - FIPS 202 (SHA-3, SHAKE), from NIST's "Examples with Intermediate Values"
//!   (SHA3-224_1600.pdf ... SHAKE256_Msg1600.pdf): SHA3-224, SHA3-256,
//!   SHA3-384 and SHA3-512 of the 1600-bit message (printed as the bit string
//!   11000101 repeated, i.e. 200 bytes of 0xA3), and SHAKE128 and SHAKE256 of
//!   the empty message and of the 1600-bit message with 4096-bit outputs,
//!   long enough to refill the sponge several times (rates of 1344 and 1088
//!   bits). The empty-message SHA-3 digests and short SHAKE prefixes are
//!   already pinned by the unit tests in `src/hash/sha3.rs`.
//!
//! Every digest is computed in one call and again incrementally, in chunk
//! sizes that straddle block and rate boundaries; SHAKE output is also
//! squeezed in uneven pieces.

mod common;

use common::decode_hex;
use cryptography::{
    Digest, Md5, Ripemd160, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Sha512, Sha512_224, Sha512_256, Shake128, Shake256, Xof,
};

/// FIPS 180-4 examples, "Two Block Message Sample" for SHA-1, SHA-224 and
/// SHA-256 (448 bits).
const MESSAGE_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/// FIPS 180-4 examples, "Two Block Message Sample" for SHA-384, SHA-512,
/// SHA-512/224 and SHA-512/256 (896 bits).
const MESSAGE_896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/// FIPS 180-2 "Long Message" examples and RIPEMD-160 Appendix B: one million
/// repetitions of "a".
fn million_a() -> Vec<u8> {
    vec![b'a'; 1_000_000]
}

/// FIPS 202 examples: the 1600-bit message, 200 bytes of 0xA3.
fn message_1600() -> Vec<u8> {
    vec![0xA3; 200]
}

/// Split `message` into consecutive pieces of the given sizes, cycling.
fn pieces<'a>(message: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = message;
    for &size in sizes.iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (piece, tail) = rest.split_at(size.min(rest.len()));
        out.push(piece);
        rest = tail;
    }
    out
}

/// One-call and incremental digests of `message` must equal `expected`.
fn check_digest<H: Digest>(message: &[u8], expected: &str, label: &str) {
    let expected = decode_hex(expected);
    assert_eq!(H::OUTPUT_LEN, expected.len(), "{label}: digest length");
    assert_eq!(H::digest(message), expected, "{label}: one call");
    let mut hasher = H::new();
    for piece in pieces(message, &[1, 63, 64, 65, 127, 129]) {
        hasher.update(piece);
    }
    let mut out = vec![0u8; H::OUTPUT_LEN];
    hasher.finalize_into(&mut out);
    assert_eq!(out, expected, "{label}: incremental");
}

/// One-call and piecewise absorb/squeeze of 512 output bytes (4096 bits).
fn check_xof<X: Xof>(new: fn() -> X, message: &[u8], expected: &str, label: &str) {
    let expected = decode_hex(expected);
    assert_eq!(expected.len(), 512, "{label}: 4096-bit output");

    let mut xof = new();
    xof.update(message);
    let mut out = vec![0u8; expected.len()];
    xof.squeeze(&mut out);
    assert_eq!(out, expected, "{label}: one squeeze");

    // Absorb in pieces, then squeeze pieces that end 1 byte short of, and
    // start 1 byte past, the rate boundaries of both SHAKE128 (168 bytes)
    // and SHAKE256 (136 bytes).
    let mut xof = new();
    for piece in pieces(message, &[1, 70, 129]) {
        xof.update(piece);
    }
    let mut out = Vec::new();
    for size in [1, 166, 2, 200, 143] {
        let mut piece = vec![0u8; size];
        xof.squeeze(&mut piece);
        out.extend_from_slice(&piece);
    }
    assert_eq!(out, expected, "{label}: piecewise");
}

/// NIST FIPS 180-4 example SHA1.pdf, "Two Block Message Sample", message digest.
const SHA1_448_BIT: &str = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

/// SHA-1 of the 448-bit message (SHA1.pdf).
#[test]
fn sha1_448_bit_message() {
    check_digest::<Sha1>(MESSAGE_448, SHA1_448_BIT, "SHA-1, 448-bit message");
}

/// NIST FIPS 180-4 example SHA224.pdf, "Two Block Message Sample", message digest.
const SHA224_448_BIT: &str = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";

/// SHA-224 of the 448-bit message (SHA224.pdf).
#[test]
fn sha224_448_bit_message() {
    check_digest::<Sha224>(MESSAGE_448, SHA224_448_BIT, "SHA-224, 448-bit message");
}

/// NIST FIPS 180-4 example SHA256.pdf, "Two Block Message Sample", message digest.
const SHA256_448_BIT: &str = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

/// SHA-256 of the 448-bit message (SHA256.pdf).
#[test]
fn sha256_448_bit_message() {
    check_digest::<Sha256>(MESSAGE_448, SHA256_448_BIT, "SHA-256, 448-bit message");
}

/// NIST FIPS 180-4 example SHA384.pdf, "Two Block Message Sample", message digest.
const SHA384_896_BIT: &str = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
    fcc7c71a557e2db966c3e9fa91746039";

/// SHA-384 of the 896-bit message (SHA384.pdf).
#[test]
fn sha384_896_bit_message() {
    check_digest::<Sha384>(MESSAGE_896, SHA384_896_BIT, "SHA-384, 896-bit message");
}

/// NIST FIPS 180-4 example SHA512.pdf, "Two Block Message Sample", message digest.
const SHA512_896_BIT: &str = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
    501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

/// SHA-512 of the 896-bit message (SHA512.pdf).
#[test]
fn sha512_896_bit_message() {
    check_digest::<Sha512>(MESSAGE_896, SHA512_896_BIT, "SHA-512, 896-bit message");
}

/// NIST FIPS 180-4 example SHA512_224.pdf, "Two Block Message Sample", message digest.
const SHA512_224_896_BIT: &str = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9";

/// SHA-512/224 of the 896-bit message (SHA512_224.pdf).
#[test]
fn sha512_224_896_bit_message() {
    check_digest::<Sha512_224>(
        MESSAGE_896,
        SHA512_224_896_BIT,
        "SHA-512/224, 896-bit message",
    );
}

/// NIST FIPS 180-4 example SHA512_256.pdf, "Two Block Message Sample", message digest.
const SHA512_256_896_BIT: &str = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a";

/// SHA-512/256 of the 896-bit message (SHA512_256.pdf).
#[test]
fn sha512_256_896_bit_message() {
    check_digest::<Sha512_256>(
        MESSAGE_896,
        SHA512_256_896_BIT,
        "SHA-512/256, 896-bit message",
    );
}

/// FIPS 180-2 Appendix A.3, "SHA-1 Example (Long Message)".
const SHA1_MILLION_A: &str = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";

/// SHA-1 of one million "a" (FIPS 180-2 Appendix A.3, "SHA-1 Example (Long Message)")
#[test]
fn sha1_million_a() {
    check_digest::<Sha1>(&million_a(), SHA1_MILLION_A, "SHA-1, one million a");
}

/// FIPS 180-2 Change Notice 1, "SHA-224 Example (Long Message)".
const SHA224_MILLION_A: &str = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";

/// SHA-224 of one million "a" (FIPS 180-2 Change Notice 1, "SHA-224 Example (Long Message)")
#[test]
fn sha224_million_a() {
    check_digest::<Sha224>(&million_a(), SHA224_MILLION_A, "SHA-224, one million a");
}

/// FIPS 180-2 Appendix B.3, "SHA-256 Example (Long Message)".
const SHA256_MILLION_A: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

/// SHA-256 of one million "a" (FIPS 180-2 Appendix B.3, "SHA-256 Example (Long Message)")
#[test]
fn sha256_million_a() {
    check_digest::<Sha256>(&million_a(), SHA256_MILLION_A, "SHA-256, one million a");
}

/// FIPS 180-2 Appendix D.3, "SHA-384 Example (Long Message)".
const SHA384_MILLION_A: &str = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b\
    07b8b3dc38ecc4ebae97ddd87f3d8985";

/// SHA-384 of one million "a" (FIPS 180-2 Appendix D.3, "SHA-384 Example (Long Message)")
#[test]
fn sha384_million_a() {
    check_digest::<Sha384>(&million_a(), SHA384_MILLION_A, "SHA-384, one million a");
}

/// FIPS 180-2 Appendix C.3, "SHA-512 Example (Long Message)".
const SHA512_MILLION_A: &str = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
    de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

/// SHA-512 of one million "a" (FIPS 180-2 Appendix C.3, "SHA-512 Example (Long Message)")
#[test]
fn sha512_million_a() {
    check_digest::<Sha512>(&million_a(), SHA512_MILLION_A, "SHA-512, one million a");
}

/// RFC 1321 Appendix A.5: MD5 ("a").
#[test]
fn md5_rfc1321_a5_1() {
    check_digest::<Md5>(b"a", "0cc175b9c0f1b6a831c399e269772661", "MD5 test suite");
}

/// RFC 1321 Appendix A.5: MD5 ("abcdefghijklmnopqrstuvwxyz").
#[test]
fn md5_rfc1321_a5_2() {
    check_digest::<Md5>(
        b"abcdefghijklmnopqrstuvwxyz",
        "c3fcd3d76192e4007dfb496cca67e13b",
        "MD5 test suite",
    );
}

/// RFC 1321 Appendix A.5: MD5 ("ABCDEFGHIJKLMNOPQRST...").
#[test]
fn md5_rfc1321_a5_3() {
    check_digest::<Md5>(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "MD5 test suite",
    );
}

/// RFC 1321 Appendix A.5: MD5 ("12345678901234567890...").
#[test]
fn md5_rfc1321_a5_4() {
    check_digest::<Md5>(
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57edf4a22be3c955ac49da2e2107b67a",
        "MD5 test suite",
    );
}

/// RIPEMD-160 Appendix B: "a".
#[test]
fn ripemd160_appendix_b_1() {
    check_digest::<Ripemd160>(
        b"a",
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        "RIPEMD-160",
    );
}

/// RIPEMD-160 Appendix B: "abcdefghijklmnopqrstuvwxyz".
#[test]
fn ripemd160_appendix_b_2() {
    check_digest::<Ripemd160>(
        b"abcdefghijklmnopqrstuvwxyz",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        "RIPEMD-160",
    );
}

/// RIPEMD-160 Appendix B: "abcdbcdecdefdefgefgh...".
#[test]
fn ripemd160_appendix_b_3() {
    check_digest::<Ripemd160>(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "RIPEMD-160",
    );
}

/// RIPEMD-160 Appendix B: "ABCDEFGHIJKLMNOPQRST...".
#[test]
fn ripemd160_appendix_b_4() {
    check_digest::<Ripemd160>(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "RIPEMD-160",
    );
}

/// RIPEMD-160 Appendix B: 8 times "1234567890".
#[test]
fn ripemd160_appendix_b_5() {
    check_digest::<Ripemd160>(
        "1234567890".repeat(8).as_bytes(),
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        "RIPEMD-160",
    );
}

/// RIPEMD-160 Appendix B: 1 million times "a".
#[test]
fn ripemd160_appendix_b_6() {
    check_digest::<Ripemd160>(
        &million_a(),
        "52783243c1697bdbe16d37f97f68f08325dc1528",
        "RIPEMD-160",
    );
}

/// NIST FIPS 202 example SHA3-224_1600.pdf, "Hash val".
const SHA3_224_1600_BIT: &str = "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0";

/// SHA3-224 of the 1600-bit message (SHA3-224_1600.pdf).
#[test]
fn sha3_224_1600_bit_message() {
    check_digest::<Sha3_224>(&message_1600(), SHA3_224_1600_BIT, "SHA3-224_1600");
}

/// NIST FIPS 202 example SHA3-256_1600.pdf, "Hash val".
const SHA3_256_1600_BIT: &str = "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787";

/// SHA3-256 of the 1600-bit message (SHA3-256_1600.pdf).
#[test]
fn sha3_256_1600_bit_message() {
    check_digest::<Sha3_256>(&message_1600(), SHA3_256_1600_BIT, "SHA3-256_1600");
}

/// NIST FIPS 202 example SHA3-384_1600.pdf, "Hash val".
const SHA3_384_1600_BIT: &str = "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd\
    76197a31fd55ee989f2d7050dd473e8f";

/// SHA3-384 of the 1600-bit message (SHA3-384_1600.pdf).
#[test]
fn sha3_384_1600_bit_message() {
    check_digest::<Sha3_384>(&message_1600(), SHA3_384_1600_BIT, "SHA3-384_1600");
}

/// NIST FIPS 202 example SHA3-512_1600.pdf, "Hash val".
const SHA3_512_1600_BIT: &str = "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8\
    1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00";

/// SHA3-512 of the 1600-bit message (SHA3-512_1600.pdf).
#[test]
fn sha3_512_1600_bit_message() {
    check_digest::<Sha3_512>(&message_1600(), SHA3_512_1600_BIT, "SHA3-512_1600");
}

/// NIST FIPS 202 example SHAKE128_Msg0.pdf, 4096-bit "Output val".
const SHAKE128_MSG0: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\
    3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
    35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2\
    badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea\
    17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef\
    aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d\
    ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9\
    22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619\
    f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b\
    1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f\
    1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06\
    bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9\
    d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2\
    e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e34\
    5db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b4\
    43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f";

/// SHAKE128, empty message, 4096-bit output (SHAKE128_Msg0.pdf).
#[test]
fn shake128_msg0_4096_bit_output() {
    let message: &[u8] = b"";
    check_xof(Shake128::new, message, SHAKE128_MSG0, "SHAKE128_Msg0");
    let mut out = [0u8; 512];
    Shake128::digest(message, &mut out);
    assert_eq!(
        out.to_vec(),
        decode_hex(SHAKE128_MSG0),
        "SHAKE128_Msg0: Shake128::digest"
    );
}

/// NIST FIPS 202 example SHAKE128_Msg1600.pdf, 4096-bit "Output val".
const SHAKE128_MSG1600: &str = "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037\
    cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846\
    7f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb871802\
    13fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270\
    c904556bfcb47a7d40778d390923642b3cbd0579e60908d5a000c1d08b98ef93\
    3f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db\
    0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d\
    71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6ae\
    a259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8\
    265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa7\
    0178f0946c9bf6ca8751793479f6b537737e40b6ed28511d8a2d7e73eb75f8da\
    ac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb\
    188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7\
    abedde6e2c0711cab36be5acb1a5a11a4b1db08ba6982efccd716929a7741cfc\
    63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a\
    44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439";

/// SHAKE128, 1600-bit message, 4096-bit output (SHAKE128_Msg1600.pdf).
#[test]
fn shake128_msg1600_4096_bit_output() {
    let message: &[u8] = &message_1600();
    check_xof(Shake128::new, message, SHAKE128_MSG1600, "SHAKE128_Msg1600");
    let mut out = [0u8; 512];
    Shake128::digest(message, &mut out);
    assert_eq!(
        out.to_vec(),
        decode_hex(SHAKE128_MSG1600),
        "SHAKE128_Msg1600: Shake128::digest"
    );
}

/// NIST FIPS 202 example SHAKE256_Msg0.pdf, 4096-bit "Output val".
const SHAKE256_MSG0: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
    d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\
    141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853\
    349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86\
    f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6\
    77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c\
    aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2\
    03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f\
    5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b\
    f9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dc\
    f722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11\
    f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837\
    143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db7\
    8f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274\
    ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bd\
    ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a";

/// SHAKE256, empty message, 4096-bit output (SHAKE256_Msg0.pdf).
#[test]
fn shake256_msg0_4096_bit_output() {
    let message: &[u8] = b"";
    check_xof(Shake256::new, message, SHAKE256_MSG0, "SHAKE256_Msg0");
    let mut out = [0u8; 512];
    Shake256::digest(message, &mut out);
    assert_eq!(
        out.to_vec(),
        decode_hex(SHAKE256_MSG0),
        "SHAKE256_Msg0: Shake256::digest"
    );
}

/// NIST FIPS 202 example SHAKE256_Msg1600.pdf, 4096-bit "Output val".
const SHAKE256_MSG1600: &str = "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d\
    2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b\
    1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628\
    001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317\
    d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b5\
    6853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b\
    61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfaf\
    a1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e58\
    9f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea84715\
    6d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364\
    ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d749\
    0499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f\
    149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505\
    c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f\
    2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e0807\
    6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";

/// SHAKE256, 1600-bit message, 4096-bit output (SHAKE256_Msg1600.pdf).
#[test]
fn shake256_msg1600_4096_bit_output() {
    let message: &[u8] = &message_1600();
    check_xof(Shake256::new, message, SHAKE256_MSG1600, "SHAKE256_Msg1600");
    let mut out = [0u8; 512];
    Shake256::digest(message, &mut out);
    assert_eq!(
        out.to_vec(),
        decode_hex(SHAKE256_MSG1600),
        "SHAKE256_Msg1600: Shake256::digest"
    );
}
