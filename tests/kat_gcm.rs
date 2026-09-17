//! GCM known answers from D. McGrew and J. Viega, "The Galois/Counter Mode of
//! Operation (GCM)", the submission to NIST that SP 800-38D cites, revised
//! May 31, 2005, Appendix B "AES Test Vectors", Test Cases 3-18.
//!
//! The document is `pubs/mcgrew-viega-2005-gcm-revised-spec.pdf` (SHA-256
//! `327e3c9363c268fae64e285e2f56f882bb6e3e04f81ef8098521f44c8e2b6c37`), the
//! Internet Archive's 2016-04-09 capture of
//! `csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf`;
//! csrc.nist.gov does not serve the document itself.
//! Every K, P, A, IV, C and T below was checked digit by digit against
//! Appendix B of that PDF (the values were extracted from its text and
//! compared mechanically), as were Test Cases 1, 2 and 4 in
//! `src/modes/mod.rs`.
//!
//! Test Cases 1 and 2 (AES-128, empty and one-block zero plaintext) are
//! pinned by the unit tests in `src/modes/mod.rs`. The cases here cover
//! AES-128 (3-6), AES-192 (7-12) and AES-256 (13-18). Cases 4-6, 10-12 and
//! 16-18 encrypt 60 bytes, a partial final block, under 20 bytes of AAD;
//! cases 5, 11 and 17 (8-byte IV) and 6, 12 and 18 (60-byte IV) derive the
//! pre-counter block by GHASH instead of `IV || 0^31 || 1`.
//!
//! Every case runs through both GHASH back ends, `Gcm` and `GcmVt`: encrypt,
//! `compute_tag` over the published ciphertext, decrypt, and then refuse the
//! ciphertext once its tag, its AAD or its body is altered, or the tag is
//! shortened.

mod common;

use common::decode_hex;
use cryptography::{Aes128, Aes192, Aes256, BlockCipher, Gcm, GcmVt};

struct Case {
    number: u32,
    key: &'static str,
    plaintext: &'static str,
    aad: &'static str,
    iv: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

const CASES: [Case; 16] = [
    // McGrew & Viega, GCM specification, Appendix B, Test Case 3:
    // AES-128, four full blocks, no AAD, 96-bit IV.
    Case {
        number: 3,
        key: "feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                    21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 4:
    // AES-128, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
    Case {
        number: 4,
        key: "feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                    21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        tag: "5bc94fbc3221a5db94fae95ae7121a47",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 5:
    // AES-128, as Test Case 4 with an 8-byte IV.
    Case {
        number: 5,
        key: "feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbad",
        ciphertext: "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
                    73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        tag: "3612d2e79e3b0785561be14aaca2fccb",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 6:
    // AES-128, as Test Case 4 with a 60-byte IV.
    Case {
        number: 6,
        key: "feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
            c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        ciphertext: "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7\
                    01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        tag: "619cc5aefffe0bfa462af43c1699d050",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 7:
    // AES-192, all-zero key, empty plaintext, no AAD.
    Case {
        number: 7,
        key: "000000000000000000000000000000000000000000000000",
        plaintext: "",
        aad: "",
        iv: "000000000000000000000000",
        ciphertext: "",
        tag: "cd33b28ac773f74ba00ed1f312572435",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 8:
    // AES-192, all-zero key, one all-zero block.
    Case {
        number: 8,
        key: "000000000000000000000000000000000000000000000000",
        plaintext: "00000000000000000000000000000000",
        aad: "",
        iv: "000000000000000000000000",
        ciphertext: "98e7247c07f0fe411c267e4384b0f600",
        tag: "2ff58d80033927ab8ef4d4587514f0fb",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 9:
    // AES-192, four full blocks, no AAD, 96-bit IV.
    Case {
        number: 9,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                    7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        tag: "9924a7c8587336bfb118024db8674a14",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 10:
    // AES-192, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
    Case {
        number: 10,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                    7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        tag: "2519498e80f1478f37ba55bd6d27618c",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 11:
    // AES-192, as Test Case 4 with an 8-byte IV.
    Case {
        number: 11,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbad",
        ciphertext: "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057\
                    fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        tag: "65dcc57fcf623a24094fcca40d3533f8",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 12:
    // AES-192, as Test Case 4 with a 60-byte IV.
    Case {
        number: 12,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
            c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        ciphertext: "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e45\
                    81e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
        tag: "dcf566ff291c25bbb8568fc3d376a6d9",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 13:
    // AES-256, all-zero key, empty plaintext, no AAD.
    Case {
        number: 13,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        plaintext: "",
        aad: "",
        iv: "000000000000000000000000",
        ciphertext: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 14:
    // AES-256, all-zero key, one all-zero block.
    Case {
        number: 14,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        plaintext: "00000000000000000000000000000000",
        aad: "",
        iv: "000000000000000000000000",
        ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 15:
    // AES-256, four full blocks, no AAD, 96-bit IV.
    Case {
        number: 15,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 16:
    // AES-256, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
    Case {
        number: 16,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbaddecaf888",
        ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 17:
    // AES-256, as Test Case 4 with an 8-byte IV.
    Case {
        number: 17,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "cafebabefacedbad",
        ciphertext: "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
                    feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        tag: "3a337dbf46a792c45e454913fe2ea8f2",
    },
    // McGrew & Viega, GCM specification, Appendix B, Test Case 18:
    // AES-256, as Test Case 4 with a 60-byte IV.
    Case {
        number: 18,
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        iv: "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
            c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        ciphertext: "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
                    0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        tag: "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
    },
];

fn aes128(key: &[u8]) -> Aes128 {
    Aes128::new(&key.try_into().expect("128-bit key"))
}

fn aes192(key: &[u8]) -> Aes192 {
    Aes192::new(&key.try_into().expect("192-bit key"))
}

fn aes256(key: &[u8]) -> Aes256 {
    Aes256::new(&key.try_into().expect("256-bit key"))
}

/// Encrypt, recompute the tag over the published ciphertext, and decrypt
/// with one GCM back end.
macro_rules! check_backend {
    ($mode:expr, $case:expr, $backend:literal) => {{
        let mode = $mode;
        let case: &Case = $case;
        let label = format!("Test Case {} ({})", case.number, $backend);
        let iv = decode_hex(case.iv);
        let aad = decode_hex(case.aad);
        let plaintext = decode_hex(case.plaintext);
        let ciphertext = decode_hex(case.ciphertext);
        let tag: [u8; 16] = decode_hex(case.tag).try_into().expect("128-bit tag");

        let mut data = plaintext.clone();
        let sealed_tag = mode.encrypt(&iv, &aad, &mut data);
        assert_eq!(data, ciphertext, "{label}: ciphertext");
        assert_eq!(sealed_tag, tag, "{label}: tag");
        assert_eq!(
            mode.compute_tag(&iv, &aad, &ciphertext),
            tag,
            "{label}: compute_tag"
        );
        assert!(
            mode.decrypt(&iv, &aad, &mut data, &tag),
            "{label}: decrypt rejected"
        );
        assert_eq!(data, plaintext, "{label}: decrypted plaintext");

        // Refusals: each alteration must be rejected with the buffer intact.
        let mut forged_tag = tag;
        forged_tag[15] ^= 0x01;
        let mut data = ciphertext.clone();
        assert!(
            !mode.decrypt(&iv, &aad, &mut data, &forged_tag),
            "{label}: altered tag accepted"
        );
        assert_eq!(data, ciphertext, "{label}: buffer changed on altered tag");

        let mut data = ciphertext.clone();
        assert!(
            !mode.decrypt(&iv, &aad, &mut data, &tag[..15]),
            "{label}: 15-byte tag accepted"
        );
        assert_eq!(data, ciphertext, "{label}: buffer changed on short tag");

        let mut altered_aad = aad.clone();
        altered_aad.push(0x00);
        let mut data = ciphertext.clone();
        assert!(
            !mode.decrypt(&iv, &altered_aad, &mut data, &tag),
            "{label}: extended AAD accepted"
        );
        assert_eq!(data, ciphertext, "{label}: buffer changed on extended AAD");
        if !aad.is_empty() {
            altered_aad.pop();
            altered_aad[0] ^= 0x80;
            let mut data = ciphertext.clone();
            assert!(
                !mode.decrypt(&iv, &altered_aad, &mut data, &tag),
                "{label}: altered AAD accepted"
            );
            assert_eq!(data, ciphertext, "{label}: buffer changed on altered AAD");
        }

        if !ciphertext.is_empty() {
            let mut altered = ciphertext.clone();
            altered[0] ^= 0x01;
            let mut data = altered.clone();
            assert!(
                !mode.decrypt(&iv, &aad, &mut data, &tag),
                "{label}: altered ciphertext accepted"
            );
            assert_eq!(
                data, altered,
                "{label}: buffer changed on altered ciphertext"
            );

            let mut truncated = ciphertext[..ciphertext.len() - 1].to_vec();
            let snapshot = truncated.clone();
            assert!(
                !mode.decrypt(&iv, &aad, &mut truncated, &tag),
                "{label}: truncated ciphertext accepted"
            );
            assert_eq!(truncated, snapshot, "{label}: buffer changed on truncation");
        }
    }};
}

fn check<C: BlockCipher>(number: u32, cipher: fn(&[u8]) -> C) {
    let case = CASES
        .iter()
        .find(|c| c.number == number)
        .expect("test case in table");
    let key = decode_hex(case.key);
    check_backend!(Gcm::new(cipher(&key)), case, "Gcm");
    check_backend!(GcmVt::new(cipher(&key)), case, "GcmVt");
}

/// Test Case 3: AES-128, four full blocks, no AAD, 96-bit IV.
#[test]
fn test_case_03() {
    check(3, aes128);
}

/// Test Case 4: AES-128, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
#[test]
fn test_case_04() {
    check(4, aes128);
}

/// Test Case 5: AES-128, as Test Case 4 with an 8-byte IV.
#[test]
fn test_case_05() {
    check(5, aes128);
}

/// Test Case 6: AES-128, as Test Case 4 with a 60-byte IV.
#[test]
fn test_case_06() {
    check(6, aes128);
}

/// Test Case 7: AES-192, all-zero key, empty plaintext, no AAD.
#[test]
fn test_case_07() {
    check(7, aes192);
}

/// Test Case 8: AES-192, all-zero key, one all-zero block.
#[test]
fn test_case_08() {
    check(8, aes192);
}

/// Test Case 9: AES-192, four full blocks, no AAD, 96-bit IV.
#[test]
fn test_case_09() {
    check(9, aes192);
}

/// Test Case 10: AES-192, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
#[test]
fn test_case_10() {
    check(10, aes192);
}

/// Test Case 11: AES-192, as Test Case 4 with an 8-byte IV.
#[test]
fn test_case_11() {
    check(11, aes192);
}

/// Test Case 12: AES-192, as Test Case 4 with a 60-byte IV.
#[test]
fn test_case_12() {
    check(12, aes192);
}

/// Test Case 13: AES-256, all-zero key, empty plaintext, no AAD.
#[test]
fn test_case_13() {
    check(13, aes256);
}

/// Test Case 14: AES-256, all-zero key, one all-zero block.
#[test]
fn test_case_14() {
    check(14, aes256);
}

/// Test Case 15: AES-256, four full blocks, no AAD, 96-bit IV.
#[test]
fn test_case_15() {
    check(15, aes256);
}

/// Test Case 16: AES-256, 60-byte plaintext (partial final block), 20 bytes of AAD, 96-bit IV.
#[test]
fn test_case_16() {
    check(16, aes256);
}

/// Test Case 17: AES-256, as Test Case 4 with an 8-byte IV.
#[test]
fn test_case_17() {
    check(17, aes256);
}

/// Test Case 18: AES-256, as Test Case 4 with a 60-byte IV.
#[test]
fn test_case_18() {
    check(18, aes256);
}
