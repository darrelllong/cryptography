//! RFC 5903, "Elliptic Curve Groups modulo a Prime (ECP Groups) for IKE and
//! IKEv2" (D. Fu, J. Solinas, June 2010), section 8: ECDH test vectors for the
//! 256-, 384- and 521-bit random ECP groups (NIST P-256, P-384, P-521).
//!
//! Each vector gives the initiator's private key `i` and public key `g^i`, the
//! responder's `r` and `g^r`, the IKE key-exchange payloads carrying the public
//! keys, and the common value `g^ir` whose x-coordinate is the shared secret.
//! The values keep the RFC's line breaks and eight-digit grouping.
//!
//! Every vector is checked twice: through the curve arithmetic
//! (`CurveParams::scalar_mul`, `CurveParams::diffie_hellman`), and through the
//! `Ecdh` key types, whose private keys are imported from the RFC's raw
//! scalars `i` and `r` by `Ecdh::from_secret_scalar`.

mod common;

use common::decode_hex;
use cryptography::vt::{p256, p384, p521, AffinePoint, BigUint, CurveParams, Ecdh, EcdhPublicKey};

struct Group {
    section: &'static str,
    group_id: u16,
    curve: fn() -> CurveParams,
    i: &'static str,
    gix: &'static str,
    giy: &'static str,
    kei: &'static str,
    r: &'static str,
    grx: &'static str,
    gry: &'static str,
    ker: &'static str,
    girx: &'static str,
    giry: &'static str,
}

/// RFC 5903 section 8.1, "256-Bit Random ECP Group" (IANA group 19).
const P256: Group = Group {
    section: "8.1",
    group_id: 19,
    curve: p256,
    i: "C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433",
    gix: "DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180",
    giy: "5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3",
    kei: concat!(
        "00000048 00130000 DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF",
        "945D0C37 72581180 5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58",
        "389E0577 B8990BB3",
    ),
    r: "C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53",
    grx: "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63",
    gry: "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB",
    ker: concat!(
        "00000048 00130000 D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C",
        "736FC755 4494BF63 56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83",
        "53E74F33 039872AB",
    ),
    girx: "D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE",
    giry: "522BDE0A F0D8585B 8DEF9C18 3B5AE38F 50235206 A8674ECB 5D98EDB2 0EB153A2",
};

/// RFC 5903 section 8.2, "384-Bit Random ECP Group" (IANA group 20).
const P384: Group = Group {
    section: "8.2",
    group_id: 20,
    curve: p384,
    i: concat!(
        "099F3C70 34D4A2C6 99884D73 A375A67F 7624EF7C 6B3C0F16 0647B674 14DCE655",
        "E35B5380 41E649EE 3FAEF896 783AB194",
    ),
    gix: concat!(
        "667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3 1634FE72 B4C55EE6",
        "DE3AC808 ACB4BDB4 C88732AE E95F41AA",
    ),
    giy: concat!(
        "9482ED1F C0EEB9CA FC498462 5CCFC23F 65032149 E0E144AD A0241815 35A0F38E",
        "EB9FCFF3 C2C947DA E69B4C63 4573A81C",
    ),
    kei: concat!(
        "00000068 00140000 667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3",
        "1634FE72 B4C55EE6 DE3AC808 ACB4BDB4 C88732AE E95F41AA 9482ED1F C0EEB9CA",
        "FC498462 5CCFC23F 65032149 E0E144AD A0241815 35A0F38E EB9FCFF3 C2C947DA",
        "E69B4C63 4573A81C",
    ),
    r: concat!(
        "41CB0779 B4BDB85D 47846725 FBEC3C94 30FAB46C C8DC5060 855CC9BD A0AA2942",
        "E0308312 916B8ED2 960E4BD5 5A7448FC",
    ),
    grx: concat!(
        "E558DBEF 53EECDE3 D3FCCFC1 AEA08A89 A987475D 12FD950D 83CFA417 32BC509D",
        "0D1AC43A 0336DEF9 6FDA41D0 774A3571",
    ),
    gry: concat!(
        "DCFBEC7A ACF31964 72169E83 8430367F 66EEBE3C 6E70C416 DD5F0C68 759DD1FF",
        "F83FA401 42209DFF 5EAAD96D B9E6386C",
    ),
    ker: concat!(
        "00000068 00140000 E558DBEF 53EECDE3 D3FCCFC1 AEA08A89 A987475D 12FD950D",
        "83CFA417 32BC509D 0D1AC43A 0336DEF9 6FDA41D0 774A3571 DCFBEC7A ACF31964",
        "72169E83 8430367F 66EEBE3C 6E70C416 DD5F0C68 759DD1FF F83FA401 42209DFF",
        "5EAAD96D B9E6386C",
    ),
    girx: concat!(
        "11187331 C279962D 93D60424 3FD592CB 9D0A926F 422E4718 7521287E 7156C5C4",
        "D6031355 69B9E9D0 9CF5D4A2 70F59746",
    ),
    giry: concat!(
        "A2A9F38E F5CAFBE2 347CF7EC 24BDD5E6 24BC93BF A82771F4 0D1B65D0 6256A852",
        "C983135D 4669F879 2F2C1D55 718AFBB4",
    ),
};

/// RFC 5903 section 8.3, "521-Bit Random ECP Group" (IANA group 21).
const P521: Group = Group {
    section: "8.3",
    group_id: 21,
    curve: p521,
    i: concat!(
        "0037ADE9 319A89F4 DABDB3EF 411AACCC A5123C61 ACAB57B5 393DCE47 608172A0",
        "95AA85A3 0FE1C295 2C6771D9 37BA9777 F5957B26 39BAB072 462F68C2 7A57382D",
        "4A52",
    ),
    gix: concat!(
        "0015417E 84DBF28C 0AD3C278 713349DC 7DF153C8 97A1891B D98BAB43 57C9ECBE",
        "E1E3BF42 E00B8E38 0AEAE57C 2D107564 94188594 2AF5A7F4 601723C4 195D176C",
        "ED3E",
    ),
    giy: concat!(
        "017CAE20 B6641D2E EB695786 D8C94614 6239D099 E18E1D5A 514C739D 7CB4A10A",
        "D8A78801 5AC405D7 799DC75E 7B7D5B6C F2261A6A 7F150743 8BF01BEB 6CA3926F",
        "9582",
    ),
    kei: concat!(
        "0000008C 00150000 0015417E 84DBF28C 0AD3C278 713349DC 7DF153C8 97A1891B",
        "D98BAB43 57C9ECBE E1E3BF42 E00B8E38 0AEAE57C 2D107564 94188594 2AF5A7F4",
        "601723C4 195D176C ED3E017C AE20B664 1D2EEB69 5786D8C9 46146239 D099E18E",
        "1D5A514C 739D7CB4 A10AD8A7 88015AC4 05D7799D C75E7B7D 5B6CF226 1A6A7F15",
        "07438BF0 1BEB6CA3 926F9582",
    ),
    r: concat!(
        "0145BA99 A847AF43 793FDD0E 872E7CDF A16BE30F DC780F97 BCCC3F07 8380201E",
        "9C677D60 0B343757 A3BDBF2A 3163E4C2 F869CCA7 458AA4A4 EFFC311F 5CB15168",
        "5EB9",
    ),
    grx: concat!(
        "00D0B397 5AC4B799 F5BEA16D 5E13E9AF 971D5E9B 984C9F39 728B5E57 39735A21",
        "9B97C356 436ADC6E 95BB0352 F6BE64A6 C2912D4E F2D0433C ED2B6171 640012D9",
        "460F",
    ),
    gry: concat!(
        "015C6822 6383956E 3BD066E7 97B623C2 7CE0EAC2 F551A10C 2C724D98 52077B87",
        "220B6536 C5C408A1 D2AEBB8E 86D678AE 49CB5709 1F473229 6579AB44 FCD17F0F",
        "C56A",
    ),
    ker: concat!(
        "0000008c 00150000 00D0B397 5AC4B799 F5BEA16D 5E13E9AF 971D5E9B 984C9F39",
        "728B5E57 39735A21 9B97C356 436ADC6E 95BB0352 F6BE64A6 C2912D4E F2D0433C",
        "ED2B6171 640012D9 460F015C 68226383 956E3BD0 66E797B6 23C27CE0 EAC2F551",
        "A10C2C72 4D985207 7B87220B 6536C5C4 08A1D2AE BB8E86D6 78AE49CB 57091F47",
        "32296579 AB44FCD1 7F0FC56A",
    ),
    girx: concat!(
        "01144C7D 79AE6956 BC8EDB8E 7C787C45 21CB086F A64407F9 7894E5E6 B2D79B04",
        "D1427E73 CA4BAA24 0A347868 59810C06 B3C715A3 A8CC3151 F2BEE417 996D19F3",
        "DDEA",
    ),
    giry: concat!(
        "01B901E6 B17DB294 7AC017D8 53EF1C16 74E5CFE5 9CDA18D0 78E05D1B 5242ADAA",
        "9FFC3C63 EA05EDB1 E13CE5B3 A8E50C3E B622E8DA 1B38E0BD D1F88569 D6C99BAF",
        "FA43",
    ),
};

/// The key-exchange data of an IKEv2 KE payload, after checking its 8-octet
/// prefix: the generic payload header (whose last two octets are the payload
/// length) and the two-octet Diffie-Hellman group number plus reserved octets.
fn key_exchange_data(section: &str, group_id: u16, payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() >= 8,
        "{section}: KE payload shorter than its 8-octet header"
    );
    let length = u16::from_be_bytes([payload[2], payload[3]]);
    assert_eq!(
        usize::from(length),
        payload.len(),
        "{section}: payload length"
    );
    assert_eq!(
        u16::from_be_bytes([payload[4], payload[5]]),
        group_id,
        "{section}: group"
    );
    payload[8..].to_vec()
}

fn check(group: &Group) {
    let section = group.section;
    let curve = (group.curve)();
    let (i, r) = (
        BigUint::from_be_bytes(&decode_hex(group.i)),
        BigUint::from_be_bytes(&decode_hex(group.r)),
    );
    let g_i = AffinePoint::new(
        BigUint::from_be_bytes(&decode_hex(group.gix)),
        BigUint::from_be_bytes(&decode_hex(group.giy)),
    );
    let g_r = AffinePoint::new(
        BigUint::from_be_bytes(&decode_hex(group.grx)),
        BigUint::from_be_bytes(&decode_hex(group.gry)),
    );
    let g_ir = AffinePoint::new(
        BigUint::from_be_bytes(&decode_hex(group.girx)),
        BigUint::from_be_bytes(&decode_hex(group.giry)),
    );

    // Curve arithmetic.
    let base = curve.base_point();
    assert_eq!(curve.scalar_mul(&base, &i), g_i, "{section}: g^i");
    assert_eq!(curve.scalar_mul(&base, &r), g_r, "{section}: g^r");
    assert_eq!(curve.diffie_hellman(&i, &g_r), g_ir, "{section}: (g^r)^i");
    assert_eq!(curve.diffie_hellman(&r, &g_i), g_ir, "{section}: (g^i)^r");

    // Ecdh key types, imported from the RFC's raw private scalars: the public
    // keys against g^i and g^r and against the KE payloads (RFC 5903 section 7:
    // x and y as fixed-width big-endian integers, concatenated), then agreement.
    let import = |name: &str, d: &BigUint| {
        Ecdh::from_secret_scalar(curve.clone(), d)
            .unwrap_or_else(|| panic!("{section}: {name} refused as a private scalar"))
    };
    let (initiator_public, initiator) = import("i", &i);
    let (responder_public, responder) = import("r", &r);
    assert_eq!(initiator.private_scalar(), &i, "{section}: imported i");
    assert_eq!(responder.private_scalar(), &r, "{section}: imported r");
    assert_eq!(
        initiator_public.public_point(),
        &g_i,
        "{section}: imported g^i"
    );
    assert_eq!(
        responder_public.public_point(),
        &g_r,
        "{section}: imported g^r"
    );
    let kei = key_exchange_data(section, group.group_id, &decode_hex(group.kei));
    let ker = key_exchange_data(section, group.group_id, &decode_hex(group.ker));
    let initiator_wire = initiator_public.to_wire_bytes();
    let responder_wire = responder_public.to_wire_bytes();
    assert_eq!(
        initiator_wire[0], 0x04,
        "{section}: uncompressed SEC 1 point"
    );
    assert_eq!(
        initiator_wire[1..],
        kei[..],
        "{section}: KEi key exchange data"
    );
    assert_eq!(
        responder_wire[0], 0x04,
        "{section}: uncompressed SEC 1 point"
    );
    assert_eq!(
        responder_wire[1..],
        ker[..],
        "{section}: KEr key exchange data"
    );

    let peer_i = EcdhPublicKey::from_wire_bytes(curve.clone(), &[&[0x04][..], &kei].concat())
        .expect("g^i decodes");
    let peer_r = EcdhPublicKey::from_wire_bytes(curve.clone(), &[&[0x04][..], &ker].concat())
        .expect("g^r decodes");
    let shared = decode_hex(group.girx);
    assert_eq!(shared.len(), curve.coord_len, "{section}: girx width");
    assert_eq!(
        initiator.agree_x_coordinate(&peer_r),
        Some(shared.clone()),
        "{section}: initiator"
    );
    assert_eq!(
        responder.agree_x_coordinate(&peer_i),
        Some(shared),
        "{section}: responder"
    );
}

/// RFC 5903 section 8.1: 256-bit random ECP group (P-256).
#[test]
fn section_8_1_p256() {
    check(&P256);
}

/// RFC 5903 section 8.2: 384-bit random ECP group (P-384).
#[test]
fn section_8_2_p384() {
    check(&P384);
}

/// RFC 5903 section 8.3: 521-bit random ECP group (P-521).
#[test]
fn section_8_3_p521() {
    check(&P521);
}
