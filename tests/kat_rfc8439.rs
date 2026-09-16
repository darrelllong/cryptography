//! RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols" (Y. Nir, A. Langley,
//! June 2018), Appendix A "Additional Test Vectors".
//!
//! None of these is pinned elsewhere: the unit tests in `src/` use the
//! worked examples of sections 2.3.2, 2.5.2 and 2.8.2, which are not in the
//! appendix.
//!
//! - A.1, ChaCha20 block function, test vectors #1-#5: the serialized
//!   keystream block. (The "ChaCha state at the end" is internal.)
//! - A.2, ChaCha20 encryption, test vectors #1-#3.
//! - A.3, Poly1305, test vectors #1-#11, including the reduction edge cases
//!   #5-#11, whose one-time key is printed as R followed by S.
//! - A.4, Poly1305 key generation from ChaCha20 block 0, test vectors #1-#3.
//! - A.5, ChaCha20-Poly1305 AEAD decryption, with the intermediate one-time
//!   key and Poly1305 tag the appendix prints; the same ciphertext is then
//!   refused once its tag, AAD or body is altered.

mod common;

use common::{decode_hex, decode_hex_array};
use cryptography::modes::poly1305::poly1305_mac;
use cryptography::{ChaCha20, ChaCha20Poly1305, Poly1305};

/// Declare one `#[test]` per table entry.
macro_rules! vector_tests {
    ($check:ident, $table:ident: $($name:ident => $index:literal),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                $check(&$table[$index]);
            }
        )+
    };
}

// ─── A.1 ChaCha20 block function ────────────────────────────────────────────

struct BlockVector {
    number: u32,
    key: &'static str,
    nonce: &'static str,
    counter: u32,
    keystream: &'static str,
}

const A1: [BlockVector; 5] = [
    // RFC 8439 Appendix A.1, Test Vector #1.
    BlockVector {
        number: 1,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 0,
        keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                   da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    },
    // RFC 8439 Appendix A.1, Test Vector #2.
    BlockVector {
        number: 2,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 1,
        keystream: "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
                   29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    },
    // RFC 8439 Appendix A.1, Test Vector #3.
    BlockVector {
        number: 3,
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000000",
        counter: 1,
        keystream: "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
                   8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
    },
    // RFC 8439 Appendix A.1, Test Vector #4.
    BlockVector {
        number: 4,
        key: "00ff000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 2,
        keystream: "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
                   13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
    },
    // RFC 8439 Appendix A.1, Test Vector #5.
    BlockVector {
        number: 5,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000002",
        counter: 0,
        keystream: "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
                   8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
    },
];

fn check_block(v: &BlockVector) {
    let mut chacha = ChaCha20::with_counter(
        &decode_hex_array(v.key),
        &decode_hex_array(v.nonce),
        v.counter,
    );
    assert_eq!(
        chacha.keystream_block().to_vec(),
        decode_hex(v.keystream),
        "A.1 test vector #{}",
        v.number
    );
}

vector_tests!(check_block, A1:
    a1_block_function_vector_1 => 0,
    a1_block_function_vector_2 => 1,
    a1_block_function_vector_3 => 2,
    a1_block_function_vector_4 => 3,
    a1_block_function_vector_5 => 4,
);

// ─── A.2 ChaCha20 encryption ────────────────────────────────────────────────

struct EncryptionVector {
    number: u32,
    key: &'static str,
    nonce: &'static str,
    counter: u32,
    plaintext: &'static str,
    ciphertext: &'static str,
}

const A2: [EncryptionVector; 3] = [
    // RFC 8439 Appendix A.2, Test Vector #1.
    EncryptionVector {
        number: 1,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        counter: 0,
        plaintext: "0000000000000000000000000000000000000000000000000000000000000000\
                   0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                    da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    },
    // RFC 8439 Appendix A.2, Test Vector #2.
    EncryptionVector {
        number: 2,
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000002",
        counter: 1,
        plaintext: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
                   6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
                   636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
                   20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
                   746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
                   206f6620616e204945544620616374697669747920697320636f6e7369646572\
                   656420616e20224945544620436f6e747269627574696f6e222e205375636820\
                   73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
                   747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
                   7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
                   74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
                   207768696368206172652061646472657373656420746f",
        ciphertext: "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec\
                    2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d\
                    4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950\
                    42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a\
                    d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d\
                    c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b\
                    0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c\
                    cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b\
                    c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f\
                    5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6\
                    98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab\
                    7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
    },
    // RFC 8439 Appendix A.2, Test Vector #3.
    EncryptionVector {
        number: 3,
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000000000000000002",
        counter: 42,
        plaintext: "2754776173206272696c6c69672c20616e642074686520736c6974687920746f\
                   7665730a446964206779726520616e642067696d626c6520696e207468652077\
                   6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665\
                   732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        ciphertext: "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf\
                    166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb\
                    f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77\
                    04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
    },
];

fn check_encryption(v: &EncryptionVector) {
    let (key, nonce) = (decode_hex_array(v.key), decode_hex_array(v.nonce));
    let mut data = decode_hex(v.plaintext);
    ChaCha20::with_counter(&key, &nonce, v.counter).apply_keystream(&mut data);
    assert_eq!(
        data,
        decode_hex(v.ciphertext),
        "A.2 test vector #{}: encryption",
        v.number
    );
    ChaCha20::with_counter(&key, &nonce, v.counter).apply_keystream(&mut data);
    assert_eq!(
        data,
        decode_hex(v.plaintext),
        "A.2 test vector #{}: decryption",
        v.number
    );
}

vector_tests!(check_encryption, A2:
    a2_encryption_vector_1 => 0,
    a2_encryption_vector_2 => 1,
    a2_encryption_vector_3 => 2,
);

// ─── A.3 Poly1305 ───────────────────────────────────────────────────────────

struct MacVector {
    number: u32,
    key: &'static str,
    text: &'static str,
    tag: &'static str,
}

const A3: [MacVector; 11] = [
    // RFC 8439 Appendix A.3, Test Vector #1.
    MacVector {
        number: 1,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        text: "0000000000000000000000000000000000000000000000000000000000000000\
              0000000000000000000000000000000000000000000000000000000000000000",
        tag: "00000000000000000000000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #2.
    MacVector {
        number: 2,
        key: "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
        text: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
              6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
              636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
              20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
              746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
              206f6620616e204945544620616374697669747920697320636f6e7369646572\
              656420616e20224945544620436f6e747269627574696f6e222e205375636820\
              73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
              747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
              7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
              74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
              207768696368206172652061646472657373656420746f",
        tag: "36e5f6b5c5e06070f0efca96227a863e",
    },
    // RFC 8439 Appendix A.3, Test Vector #3.
    MacVector {
        number: 3,
        key: "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
        text: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e\
              6465642062792074686520436f6e7472696275746f7220666f72207075626c69\
              636174696f6e20617320616c6c206f722070617274206f6620616e2049455446\
              20496e7465726e65742d4472616674206f722052464320616e6420616e792073\
              746174656d656e74206d6164652077697468696e2074686520636f6e74657874\
              206f6620616e204945544620616374697669747920697320636f6e7369646572\
              656420616e20224945544620436f6e747269627574696f6e222e205375636820\
              73746174656d656e747320696e636c756465206f72616c2073746174656d656e\
              747320696e20494554462073657373696f6e732c2061732077656c6c20617320\
              7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361\
              74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c\
              207768696368206172652061646472657373656420746f",
        tag: "f3477e7cd95417af89a6b8794c310cf0",
    },
    // RFC 8439 Appendix A.3, Test Vector #4.
    MacVector {
        number: 4,
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        text: "2754776173206272696c6c69672c20616e642074686520736c6974687920746f\
              7665730a446964206779726520616e642067696d626c6520696e207468652077\
              6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665\
              732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        tag: "4541669a7eaaee61e708dc7cbcc5eb62",
    },
    // RFC 8439 Appendix A.3, Test Vector #5. Key is R || S.
    MacVector {
        number: 5,
        key: concat!(
            "02000000000000000000000000000000",
            "00000000000000000000000000000000"
        ),
        text: "ffffffffffffffffffffffffffffffff",
        tag: "03000000000000000000000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #6. Key is R || S.
    MacVector {
        number: 6,
        key: concat!(
            "02000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff"
        ),
        text: "02000000000000000000000000000000",
        tag: "03000000000000000000000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #7. Key is R || S.
    MacVector {
        number: 7,
        key: concat!(
            "01000000000000000000000000000000",
            "00000000000000000000000000000000"
        ),
        text: "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff\
              11000000000000000000000000000000",
        tag: "05000000000000000000000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #8. Key is R || S.
    MacVector {
        number: 8,
        key: concat!(
            "01000000000000000000000000000000",
            "00000000000000000000000000000000"
        ),
        text: "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe\
              01010101010101010101010101010101",
        tag: "00000000000000000000000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #9. Key is R || S.
    MacVector {
        number: 9,
        key: concat!(
            "02000000000000000000000000000000",
            "00000000000000000000000000000000"
        ),
        text: "fdffffffffffffffffffffffffffffff",
        tag: "faffffffffffffffffffffffffffffff",
    },
    // RFC 8439 Appendix A.3, Test Vector #10. Key is R || S.
    MacVector {
        number: 10,
        key: concat!(
            "01000000000000000400000000000000",
            "00000000000000000000000000000000"
        ),
        text: "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000\
              0000000000000000000000000000000001000000000000000000000000000000",
        tag: "14000000000000005500000000000000",
    },
    // RFC 8439 Appendix A.3, Test Vector #11. Key is R || S.
    MacVector {
        number: 11,
        key: concat!(
            "01000000000000000400000000000000",
            "00000000000000000000000000000000"
        ),
        text: "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000\
              00000000000000000000000000000000",
        tag: "13000000000000000000000000000000",
    },
];

fn check_mac(v: &MacVector) {
    let key: [u8; 32] = decode_hex_array(v.key);
    let tag: [u8; 16] = decode_hex_array(v.tag);
    let text = decode_hex(v.text);
    assert_eq!(
        Poly1305::new(&key).compute(&text),
        tag,
        "A.3 test vector #{}",
        v.number
    );
    assert_eq!(
        poly1305_mac(&text, &key),
        tag,
        "A.3 test vector #{}: poly1305_mac",
        v.number
    );
    assert!(
        Poly1305::new(&key).verify(&text, &tag),
        "A.3 test vector #{}: verify",
        v.number
    );
}

vector_tests!(check_mac, A3:
    a3_poly1305_vector_1 => 0,
    a3_poly1305_vector_2 => 1,
    a3_poly1305_vector_3 => 2,
    a3_poly1305_vector_4 => 3,
    a3_poly1305_vector_5 => 4,
    a3_poly1305_vector_6 => 5,
    a3_poly1305_vector_7 => 6,
    a3_poly1305_vector_8 => 7,
    a3_poly1305_vector_9 => 8,
    a3_poly1305_vector_10 => 9,
    a3_poly1305_vector_11 => 10,
);

// ─── A.4 Poly1305 key generation using ChaCha20 ─────────────────────────────

struct KeyGenerationVector {
    number: u32,
    key: &'static str,
    nonce: &'static str,
    one_time_key: &'static str,
}

const A4: [KeyGenerationVector; 3] = [
    // RFC 8439 Appendix A.4, Test Vector #1.
    KeyGenerationVector {
        number: 1,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        one_time_key: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    },
    // RFC 8439 Appendix A.4, Test Vector #2.
    KeyGenerationVector {
        number: 2,
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "000000000000000000000002",
        one_time_key: "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
    },
    // RFC 8439 Appendix A.4, Test Vector #3.
    KeyGenerationVector {
        number: 3,
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000000000000000002",
        one_time_key: "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
    },
];

/// Section 2.6: the one-time key is the first 32 bytes of block 0.
fn check_key_generation(v: &KeyGenerationVector) {
    let block = ChaCha20::with_counter(&decode_hex_array(v.key), &decode_hex_array(v.nonce), 0)
        .keystream_block();
    assert_eq!(
        block[..32],
        decode_hex(v.one_time_key)[..],
        "A.4 test vector #{}",
        v.number
    );
}

vector_tests!(check_key_generation, A4:
    a4_poly1305_key_generation_vector_1 => 0,
    a4_poly1305_key_generation_vector_2 => 1,
    a4_poly1305_key_generation_vector_3 => 2,
);

// ─── A.5 ChaCha20-Poly1305 AEAD decryption ──────────────────────────────────

// RFC 8439 Appendix A.5.
const A5_KEY: &str = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
const A5_CIPHERTEXT: &str = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2\
    4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf\
    332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855\
    9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4\
    b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e\
    af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a\
    0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10\
    49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29\
    a6ad5cb4022b02709b";
const A5_NONCE: &str = "000000000102030405060708";
const A5_AAD: &str = "f33388860000000000004e91";
const A5_RECEIVED_TAG: &str = "eead9d67890cbb22392336fea1851f38";
const A5_ONE_TIME_KEY: &str = "bdf04aa95ce4de8995b14bb6a18fecaf26478f50c054f563dbc0a21e261572aa";
const A5_POLY1305_INPUT: &str = "f33388860000000000004e910000000064a0861575861af460f062c79be643bd\
    5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0\
    bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b9481\
    14ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b350638\
    3606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e9\
    9040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a\
    0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434e\
    cebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130\
    305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b00000000000000\
    0c000000000000000901000000000000";
const A5_CALCULATED_TAG: &str = "eead9d67890cbb22392336fea1851f38";
const A5_PLAINTEXT: &str = "496e7465726e65742d4472616674732061726520647261667420646f63756d65\
    6e74732076616c696420666f722061206d6178696d756d206f6620736978206d\
    6f6e74687320616e64206d617920626520757064617465642c207265706c6163\
    65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65\
    6e747320617420616e792074696d652e20497420697320696e617070726f7072\
    6961746520746f2075736520496e7465726e65742d4472616674732061732072\
    65666572656e6365206d6174657269616c206f7220746f206369746520746865\
    6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67\
    726573732e2fe2809d";

/// RFC 8439 Appendix A.5: authenticate and decrypt, checking the printed
/// one-time key and Poly1305 tag along the way, then re-encrypt.
#[test]
fn a5_aead_decryption() {
    let key: [u8; 32] = decode_hex_array(A5_KEY);
    let nonce: [u8; 12] = decode_hex_array(A5_NONCE);
    let aad = decode_hex(A5_AAD);
    let ciphertext = decode_hex(A5_CIPHERTEXT);
    let received_tag: [u8; 16] = decode_hex_array(A5_RECEIVED_TAG);
    let plaintext = decode_hex(A5_PLAINTEXT);

    let block = ChaCha20::with_counter(&key, &nonce, 0).keystream_block();
    let one_time_key: [u8; 32] = decode_hex_array(A5_ONE_TIME_KEY);
    assert_eq!(block[..32], one_time_key, "one-time Poly1305 key");
    let calculated: [u8; 16] = decode_hex_array(A5_CALCULATED_TAG);
    assert_eq!(
        Poly1305::new(&one_time_key).compute(&decode_hex(A5_POLY1305_INPUT)),
        calculated,
        "Poly1305 over the AEAD buffer"
    );

    let aead = ChaCha20Poly1305::new(&key);
    assert_eq!(
        aead.decrypt(&nonce, &aad, &ciphertext, &received_tag),
        Some(plaintext.clone()),
        "decrypt"
    );
    let (sealed, tag) = aead.encrypt(&nonce, &aad, &plaintext);
    assert_eq!(sealed, ciphertext, "re-encrypted ciphertext");
    assert_eq!(tag, received_tag, "re-encrypted tag");
}

/// RFC 8439 Appendix A.5 tampered: a flipped tag byte, an altered or
/// extended AAD, an altered or truncated ciphertext, and a tag of the wrong
/// nonce are all refused, and the in-place API leaves the buffer untouched.
#[test]
fn a5_tampering_is_refused() {
    let key: [u8; 32] = decode_hex_array(A5_KEY);
    let nonce: [u8; 12] = decode_hex_array(A5_NONCE);
    let aad = decode_hex(A5_AAD);
    let ciphertext = decode_hex(A5_CIPHERTEXT);
    let tag: [u8; 16] = decode_hex_array(A5_RECEIVED_TAG);
    let aead = ChaCha20Poly1305::new(&key);

    for i in [0usize, 7, 15] {
        let mut forged = tag;
        forged[i] ^= 0x01;
        assert_eq!(
            aead.decrypt(&nonce, &aad, &ciphertext, &forged),
            None,
            "tag byte {i} altered"
        );
    }

    let mut altered_aad = aad.clone();
    altered_aad[0] ^= 0x80;
    assert_eq!(
        aead.decrypt(&nonce, &altered_aad, &ciphertext, &tag),
        None,
        "altered AAD"
    );
    let mut extended_aad = aad.clone();
    extended_aad.push(0x00);
    assert_eq!(
        aead.decrypt(&nonce, &extended_aad, &ciphertext, &tag),
        None,
        "extended AAD"
    );
    assert_eq!(
        aead.decrypt(&nonce, &[], &ciphertext, &tag),
        None,
        "AAD removed"
    );

    let mut altered = ciphertext.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    assert_eq!(
        aead.decrypt(&nonce, &aad, &altered, &tag),
        None,
        "altered ciphertext"
    );
    assert_eq!(
        aead.decrypt(&nonce, &aad, &ciphertext[..last], &tag),
        None,
        "truncated ciphertext"
    );

    let mut other_nonce = nonce;
    other_nonce[11] ^= 0x01;
    assert_eq!(
        aead.decrypt(&other_nonce, &aad, &ciphertext, &tag),
        None,
        "other nonce"
    );

    let mut in_place = altered.clone();
    assert!(!aead.decrypt_in_place(&nonce, &aad, &mut in_place, &tag));
    assert_eq!(in_place, altered, "buffer changed on refusal");

    assert_eq!(
        aead.decrypt(&nonce, &aad, &ciphertext, &tag).as_deref(),
        Some(decode_hex(A5_PLAINTEXT).as_slice()),
        "the untouched record still opens"
    );
}
