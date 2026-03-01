//! Camellia block cipher — CRYPTREC / ISO/IEC 18033-3 / RFC 3713.
//!
//! 128-bit block cipher with three standard key sizes:
//!
//! - `Camellia128` / `Camellia128Ct`
//! - `Camellia192` / `Camellia192Ct`
//! - `Camellia256` / `Camellia256Ct`
//!
//! Camellia is a Feistel network with 18 rounds for 128-bit keys and 24 rounds
//! for 192/256-bit keys. The fast path keeps the direct 8-bit S-box table. The
//! `Ct` path evaluates the same S-box in packed ANF form so the round function
//! and key schedule avoid secret-indexed table reads.

#[rustfmt::skip]
const SBOX1: [u8; 256] = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
];

// RFC 3713 §2.4 base constants.
const SIGMA: [u64; 6] = [
    0xA09E_667F_3BCC_908B,
    0xB67A_E858_4CAA_73B2,
    0xC6EF_372F_E94F_82BE,
    0x54FF_53A5_F1D3_6F1C,
    0x10E5_27FA_DE68_2D1D,
    0xB056_88C2_B3E6_C1FD,
];

const SBOX1_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&SBOX1);

#[derive(Clone, Copy)]
struct Subkeys18 {
    kw: [u64; 4],
    k: [u64; 18],
    ke: [u64; 4],
}

#[derive(Clone, Copy)]
struct Subkeys24 {
    kw: [u64; 4],
    k: [u64; 24],
    ke: [u64; 6],
}

#[inline]
fn sbox1(x: u8) -> u8 {
    SBOX1[x as usize]
}

#[inline]
fn sbox1_ct(x: u8) -> u8 {
    crate::ct::eval_byte_sbox(&SBOX1_ANF, x)
}

#[inline]
fn sbox2(x: u8) -> u8 {
    sbox1(x).rotate_left(1)
}

#[inline]
fn sbox3(x: u8) -> u8 {
    sbox1(x).rotate_left(7)
}

#[inline]
fn sbox4(x: u8) -> u8 {
    sbox1(x.rotate_left(1))
}

#[inline]
fn sbox2_ct(x: u8) -> u8 {
    sbox1_ct(x).rotate_left(1)
}

#[inline]
fn sbox3_ct(x: u8) -> u8 {
    sbox1_ct(x).rotate_left(7)
}

#[inline]
fn sbox4_ct(x: u8) -> u8 {
    sbox1_ct(x.rotate_left(1))
}

#[inline]
fn camellia_f(input: u64, subkey: u64) -> u64 {
    let x = (input ^ subkey).to_be_bytes();

    let t1 = sbox1(x[0]);
    let t2 = sbox2(x[1]);
    let t3 = sbox3(x[2]);
    let t4 = sbox4(x[3]);
    let t5 = sbox2(x[4]);
    let t6 = sbox3(x[5]);
    let t7 = sbox4(x[6]);
    let t8 = sbox1(x[7]);

    u64::from_be_bytes([
        t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8,
        t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8,
        t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8,
        t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7,
        t1 ^ t2 ^ t6 ^ t7 ^ t8,
        t2 ^ t3 ^ t5 ^ t7 ^ t8,
        t3 ^ t4 ^ t5 ^ t6 ^ t8,
        t1 ^ t4 ^ t5 ^ t6 ^ t7,
    ])
}

#[inline]
fn camellia_f_ct(input: u64, subkey: u64) -> u64 {
    let x = (input ^ subkey).to_be_bytes();

    let t1 = sbox1_ct(x[0]);
    let t2 = sbox2_ct(x[1]);
    let t3 = sbox3_ct(x[2]);
    let t4 = sbox4_ct(x[3]);
    let t5 = sbox2_ct(x[4]);
    let t6 = sbox3_ct(x[5]);
    let t7 = sbox4_ct(x[6]);
    let t8 = sbox1_ct(x[7]);

    u64::from_be_bytes([
        t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8,
        t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8,
        t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8,
        t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7,
        t1 ^ t2 ^ t6 ^ t7 ^ t8,
        t2 ^ t3 ^ t5 ^ t7 ^ t8,
        t3 ^ t4 ^ t5 ^ t6 ^ t8,
        t1 ^ t4 ^ t5 ^ t6 ^ t7,
    ])
}

#[inline]
fn fl(x: u64, ke: u64) -> u64 {
    let (mut x1, mut x2) = split_u64_words(x);
    let (k1, k2) = split_u64_words(ke);
    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;
    (u64::from(x1) << 32) | u64::from(x2)
}

#[inline]
fn fl_inv(x: u64, ke: u64) -> u64 {
    let (mut y1, mut y2) = split_u64_words(x);
    let (k1, k2) = split_u64_words(ke);
    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);
    (u64::from(y1) << 32) | u64::from(y2)
}

#[inline]
fn halves(x: u128) -> (u64, u64) {
    let bytes = x.to_be_bytes();
    (
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
    )
}

#[inline]
fn split_u64_words(x: u64) -> (u32, u32) {
    let bytes = x.to_be_bytes();
    (
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    )
}

#[inline]
fn rot_pair(x: u128, bits: u32) -> (u64, u64) {
    halves(x.rotate_left(bits))
}

fn derive_ka(kl: u128, kr: u128, use_ct: bool) -> u128 {
    let x = kl ^ kr;
    let (mut d1, mut d2) = halves(x);
    let (kl_l, kl_r) = halves(kl);

    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d2 ^= f(d1, SIGMA[0]);
    d1 ^= f(d2, SIGMA[1]);
    d1 ^= kl_l;
    d2 ^= kl_r;
    d2 ^= f(d1, SIGMA[2]);
    d1 ^= f(d2, SIGMA[3]);

    (u128::from(d1) << 64) | u128::from(d2)
}

fn derive_kb(ka: u128, kr: u128, use_ct: bool) -> u128 {
    let (kr_l, kr_r) = halves(kr);
    let (mut d1, mut d2) = halves(ka);

    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d1 ^= kr_l;
    d2 ^= kr_r;
    d2 ^= f(d1, SIGMA[4]);
    d1 ^= f(d2, SIGMA[5]);

    (u128::from(d1) << 64) | u128::from(d2)
}

fn expand_128(key: &[u8; 16], use_ct: bool) -> Subkeys18 {
    let kl = u128::from_be_bytes(*key);
    let ka = derive_ka(kl, 0, use_ct);

    let left_key_rotations = [
        rot_pair(kl, 0),
        rot_pair(kl, 15),
        rot_pair(kl, 45),
        rot_pair(kl, 60),
        rot_pair(kl, 77),
        rot_pair(kl, 94),
        rot_pair(kl, 111),
    ];
    let aux_key_rotations = [
        rot_pair(ka, 0),
        rot_pair(ka, 15),
        rot_pair(ka, 30),
        rot_pair(ka, 45),
        rot_pair(ka, 60),
        rot_pair(ka, 94),
        rot_pair(ka, 111),
    ];

    let mut out = Subkeys18 {
        kw: [0; 4],
        k: [0; 18],
        ke: [0; 4],
    };

    out.kw[0] = left_key_rotations[0].0;
    out.kw[1] = left_key_rotations[0].1;
    out.kw[2] = aux_key_rotations[6].0;
    out.kw[3] = aux_key_rotations[6].1;

    out.k[0] = aux_key_rotations[0].0;
    out.k[1] = aux_key_rotations[0].1;
    out.k[2] = left_key_rotations[1].0;
    out.k[3] = left_key_rotations[1].1;
    out.k[4] = aux_key_rotations[1].0;
    out.k[5] = aux_key_rotations[1].1;
    out.ke[0] = aux_key_rotations[2].0;
    out.ke[1] = aux_key_rotations[2].1;
    out.k[6] = left_key_rotations[2].0;
    out.k[7] = left_key_rotations[2].1;
    out.k[8] = aux_key_rotations[3].0;
    out.k[9] = left_key_rotations[3].1;
    out.k[10] = aux_key_rotations[4].0;
    out.k[11] = aux_key_rotations[4].1;
    out.ke[2] = left_key_rotations[4].0;
    out.ke[3] = left_key_rotations[4].1;
    out.k[12] = left_key_rotations[5].0;
    out.k[13] = left_key_rotations[5].1;
    out.k[14] = aux_key_rotations[5].0;
    out.k[15] = aux_key_rotations[5].1;
    out.k[16] = left_key_rotations[6].0;
    out.k[17] = left_key_rotations[6].1;

    out
}

fn expand_192_256(kl: u128, kr: u128, use_ct: bool) -> Subkeys24 {
    let ka = derive_ka(kl, kr, use_ct);
    let kb = derive_kb(ka, kr, use_ct);

    let left_key_rotations = [
        rot_pair(kl, 0),
        rot_pair(kl, 45),
        rot_pair(kl, 60),
        rot_pair(kl, 77),
        rot_pair(kl, 111),
    ];
    let right_key_rotations = [
        rot_pair(kr, 15),
        rot_pair(kr, 30),
        rot_pair(kr, 60),
        rot_pair(kr, 94),
    ];
    let aux_key_rotations = [
        rot_pair(ka, 15),
        rot_pair(ka, 45),
        rot_pair(ka, 77),
        rot_pair(ka, 94),
    ];
    let secondary_key_rotations = [
        rot_pair(kb, 0),
        rot_pair(kb, 30),
        rot_pair(kb, 60),
        rot_pair(kb, 111),
    ];

    let mut out = Subkeys24 {
        kw: [0; 4],
        k: [0; 24],
        ke: [0; 6],
    };

    out.kw[0] = left_key_rotations[0].0;
    out.kw[1] = left_key_rotations[0].1;
    out.kw[2] = secondary_key_rotations[3].0;
    out.kw[3] = secondary_key_rotations[3].1;

    out.k[0] = secondary_key_rotations[0].0;
    out.k[1] = secondary_key_rotations[0].1;
    out.k[2] = right_key_rotations[0].0;
    out.k[3] = right_key_rotations[0].1;
    out.k[4] = aux_key_rotations[0].0;
    out.k[5] = aux_key_rotations[0].1;
    out.ke[0] = right_key_rotations[1].0;
    out.ke[1] = right_key_rotations[1].1;
    out.k[6] = secondary_key_rotations[1].0;
    out.k[7] = secondary_key_rotations[1].1;
    out.k[8] = left_key_rotations[1].0;
    out.k[9] = left_key_rotations[1].1;
    out.k[10] = aux_key_rotations[1].0;
    out.k[11] = aux_key_rotations[1].1;
    out.ke[2] = left_key_rotations[2].0;
    out.ke[3] = left_key_rotations[2].1;
    out.k[12] = right_key_rotations[2].0;
    out.k[13] = right_key_rotations[2].1;
    out.k[14] = secondary_key_rotations[2].0;
    out.k[15] = secondary_key_rotations[2].1;
    out.k[16] = left_key_rotations[3].0;
    out.k[17] = left_key_rotations[3].1;
    out.ke[4] = aux_key_rotations[2].0;
    out.ke[5] = aux_key_rotations[2].1;
    out.k[18] = right_key_rotations[3].0;
    out.k[19] = right_key_rotations[3].1;
    out.k[20] = aux_key_rotations[3].0;
    out.k[21] = aux_key_rotations[3].1;
    out.k[22] = left_key_rotations[4].0;
    out.k[23] = left_key_rotations[4].1;

    out
}

fn camellia_encrypt_18(block: [u8; 16], sk: &Subkeys18, use_ct: bool) -> [u8; 16] {
    let mut d1 = u64::from_be_bytes(block[..8].try_into().unwrap());
    let mut d2 = u64::from_be_bytes(block[8..].try_into().unwrap());
    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d1 ^= sk.kw[0];
    d2 ^= sk.kw[1];

    let mut idx = 0usize;
    while idx < 6 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }
    d1 = fl(d1, sk.ke[0]);
    d2 = fl_inv(d2, sk.ke[1]);

    while idx < 12 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }
    d1 = fl(d1, sk.ke[2]);
    d2 = fl_inv(d2, sk.ke[3]);

    while idx < 18 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(d2 ^ sk.kw[2]).to_be_bytes());
    out[8..].copy_from_slice(&(d1 ^ sk.kw[3]).to_be_bytes());
    out
}

fn camellia_decrypt_18(block: [u8; 16], sk: &Subkeys18, use_ct: bool) -> [u8; 16] {
    let mut d2 = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ sk.kw[2];
    let mut d1 = u64::from_be_bytes(block[8..].try_into().unwrap()) ^ sk.kw[3];
    let f = if use_ct { camellia_f_ct } else { camellia_f };

    let mut idx = 18usize;
    while idx > 12 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }
    d2 = fl(d2, sk.ke[3]);
    d1 = fl_inv(d1, sk.ke[2]);

    while idx > 6 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }
    d2 = fl(d2, sk.ke[1]);
    d1 = fl_inv(d1, sk.ke[0]);

    while idx > 0 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(d1 ^ sk.kw[0]).to_be_bytes());
    out[8..].copy_from_slice(&(d2 ^ sk.kw[1]).to_be_bytes());
    out
}

fn camellia_encrypt_24(block: [u8; 16], sk: &Subkeys24, use_ct: bool) -> [u8; 16] {
    let mut d1 = u64::from_be_bytes(block[..8].try_into().unwrap());
    let mut d2 = u64::from_be_bytes(block[8..].try_into().unwrap());
    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d1 ^= sk.kw[0];
    d2 ^= sk.kw[1];

    let mut idx = 0usize;
    while idx < 6 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }
    d1 = fl(d1, sk.ke[0]);
    d2 = fl_inv(d2, sk.ke[1]);

    while idx < 12 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }
    d1 = fl(d1, sk.ke[2]);
    d2 = fl_inv(d2, sk.ke[3]);

    while idx < 18 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }
    d1 = fl(d1, sk.ke[4]);
    d2 = fl_inv(d2, sk.ke[5]);

    while idx < 24 {
        d2 ^= f(d1, sk.k[idx]);
        d1 ^= f(d2, sk.k[idx + 1]);
        idx += 2;
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(d2 ^ sk.kw[2]).to_be_bytes());
    out[8..].copy_from_slice(&(d1 ^ sk.kw[3]).to_be_bytes());
    out
}

fn camellia_decrypt_24(block: [u8; 16], sk: &Subkeys24, use_ct: bool) -> [u8; 16] {
    let mut d2 = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ sk.kw[2];
    let mut d1 = u64::from_be_bytes(block[8..].try_into().unwrap()) ^ sk.kw[3];
    let f = if use_ct { camellia_f_ct } else { camellia_f };

    let mut idx = 24usize;
    while idx > 18 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }
    d2 = fl(d2, sk.ke[5]);
    d1 = fl_inv(d1, sk.ke[4]);

    while idx > 12 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }
    d2 = fl(d2, sk.ke[3]);
    d1 = fl_inv(d1, sk.ke[2]);

    while idx > 6 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }
    d2 = fl(d2, sk.ke[1]);
    d1 = fl_inv(d1, sk.ke[0]);

    while idx > 0 {
        idx -= 2;
        d1 ^= f(d2, sk.k[idx + 1]);
        d2 ^= f(d1, sk.k[idx]);
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(d1 ^ sk.kw[0]).to_be_bytes());
    out[8..].copy_from_slice(&(d2 ^ sk.kw[1]).to_be_bytes());
    out
}

/// Camellia-128 fast software path.
pub struct Camellia128 {
    subkeys: Subkeys18,
}

impl Camellia128 {
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            subkeys: expand_128(key, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_18(*block, &self.subkeys, false)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_18(*block, &self.subkeys, false)
    }
}

/// Camellia-128 constant-time software path.
pub struct Camellia128Ct {
    subkeys: Subkeys18,
}

impl Camellia128Ct {
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            subkeys: expand_128(key, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_18(*block, &self.subkeys, true)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_18(*block, &self.subkeys, true)
    }
}

/// Camellia-192 fast software path.
pub struct Camellia192 {
    subkeys: Subkeys24,
}

impl Camellia192 {
    #[must_use]
    pub fn new(key: &[u8; 24]) -> Self {
        let mut kl_bytes = [0u8; 16];
        kl_bytes.copy_from_slice(&key[..16]);
        let kl = u128::from_be_bytes(kl_bytes);
        let mut tail_bytes = [0u8; 8];
        tail_bytes.copy_from_slice(&key[16..]);
        let tail = u64::from_be_bytes(tail_bytes);
        let kr = (u128::from(tail) << 64) | u128::from(!tail);
        Self {
            subkeys: expand_192_256(kl, kr, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, false)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, false)
    }
}

/// Camellia-192 constant-time software path.
pub struct Camellia192Ct {
    subkeys: Subkeys24,
}

impl Camellia192Ct {
    #[must_use]
    pub fn new(key: &[u8; 24]) -> Self {
        let mut kl_bytes = [0u8; 16];
        kl_bytes.copy_from_slice(&key[..16]);
        let kl = u128::from_be_bytes(kl_bytes);
        let mut tail_bytes = [0u8; 8];
        tail_bytes.copy_from_slice(&key[16..]);
        let tail = u64::from_be_bytes(tail_bytes);
        let kr = (u128::from(tail) << 64) | u128::from(!tail);
        Self {
            subkeys: expand_192_256(kl, kr, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, true)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, true)
    }
}

/// Camellia-256 fast software path.
pub struct Camellia256 {
    subkeys: Subkeys24,
}

impl Camellia256 {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut left_key_bytes = [0u8; 16];
        left_key_bytes.copy_from_slice(&key[..16]);
        let kl = u128::from_be_bytes(left_key_bytes);
        let mut right_key_bytes = [0u8; 16];
        right_key_bytes.copy_from_slice(&key[16..]);
        let kr = u128::from_be_bytes(right_key_bytes);
        Self {
            subkeys: expand_192_256(kl, kr, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, false)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, false)
    }
}

/// Camellia-256 constant-time software path.
pub struct Camellia256Ct {
    subkeys: Subkeys24,
}

impl Camellia256Ct {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut left_key_bytes = [0u8; 16];
        left_key_bytes.copy_from_slice(&key[..16]);
        let kl = u128::from_be_bytes(left_key_bytes);
        let mut right_key_bytes = [0u8; 16];
        right_key_bytes.copy_from_slice(&key[16..]);
        let kr = u128::from_be_bytes(right_key_bytes);
        Self {
            subkeys: expand_192_256(kl, kr, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, true)
    }

    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, true)
    }
}

/// Camellia usually refers to the 128-bit-key variant.
pub type Camellia = Camellia128;
/// Constant-time Camellia-128 alias.
pub type CamelliaCt = Camellia128Ct;

macro_rules! impl_block_cipher {
    ($name:ty) => {
        impl crate::BlockCipher for $name {
            const BLOCK_LEN: usize = 16;
            fn encrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.encrypt_block(arr));
            }
            fn decrypt(&self, block: &mut [u8]) {
                let arr: &[u8; 16] = (&*block).try_into().expect("wrong block length");
                block.copy_from_slice(&self.decrypt_block(arr));
            }
        }
    };
}

impl_block_cipher!(Camellia128);
impl_block_cipher!(Camellia128Ct);
impl_block_cipher!(Camellia192);
impl_block_cipher!(Camellia192Ct);
impl_block_cipher!(Camellia256);
impl_block_cipher!(Camellia256Ct);

impl Drop for Camellia128 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

impl Drop for Camellia128Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

impl Drop for Camellia192 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

impl Drop for Camellia192Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

impl Drop for Camellia256 {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

impl Drop for Camellia256Ct {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.subkeys.kw.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.k.as_mut_slice());
        crate::ct::zeroize_slice(self.subkeys.ke.as_mut_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h16(s: &str) -> [u8; 16] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    fn h24(s: &str) -> [u8; 24] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    fn h32(s: &str) -> [u8; 32] {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        b.try_into().unwrap()
    }

    #[test]
    fn ct_sbox_matches_table() {
        for x in 0u8..=255 {
            assert_eq!(sbox1_ct(x), sbox1(x));
        }
    }

    #[test]
    fn camellia128_kat() {
        let key = h16("0123456789abcdeffedcba9876543210");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("67673138549669730857065648eabe43");
        let cipher = Camellia128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia128_ct_kat() {
        let key = h16("0123456789abcdeffedcba9876543210");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("67673138549669730857065648eabe43");
        let cipher = Camellia128Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia192_kat() {
        let key = h24("0123456789abcdeffedcba98765432100011223344556677");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("b4993401b3e996f84ee5cee7d79b09b9");
        let cipher = Camellia192::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia192_ct_kat() {
        let key = h24("0123456789abcdeffedcba98765432100011223344556677");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("b4993401b3e996f84ee5cee7d79b09b9");
        let cipher = Camellia192Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia256_kat() {
        let key = h32("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("9acc237dff16d76c20ef7c919e3a7509");
        let cipher = Camellia256::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia256_ct_kat() {
        let key = h32("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        let pt = h16("0123456789abcdeffedcba9876543210");
        let ct = h16("9acc237dff16d76c20ef7c919e3a7509");
        let cipher = Camellia256Ct::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
    }

    #[test]
    fn camellia128_matches_openssl_ecb() {
        let key_hex = "0123456789abcdeffedcba9876543210";
        let pt_hex = "0123456789abcdeffedcba9876543210";
        let Some(expected) =
            crate::ct::run_openssl_enc("-camellia-128-ecb", key_hex, None, &h16(pt_hex))
        else {
            return;
        };

        let cipher = Camellia128::new(&h16(key_hex));
        assert_eq!(
            cipher.encrypt_block(&h16(pt_hex)).as_slice(),
            expected.as_slice()
        );
    }
}
