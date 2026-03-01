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

const fn build_sbox_anf() -> [[u128; 2]; 8] {
    let mut out = [[0u128; 2]; 8];
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let mut coeffs = [0u8; 256];
        let mut x = 0usize;
        while x < 256 {
            coeffs[x] = (SBOX1[x] >> bit_idx) & 1;
            x += 1;
        }

        let mut var = 0usize;
        while var < 8 {
            let stride = 1usize << var;
            let mut mask = 0usize;
            while mask < 256 {
                if mask & stride != 0 {
                    coeffs[mask] ^= coeffs[mask ^ stride];
                }
                mask += 1;
            }
            var += 1;
        }

        let mut lo = 0u128;
        let mut hi = 0u128;
        let mut monomial = 0usize;
        while monomial < 128 {
            lo |= (coeffs[monomial] as u128) << monomial;
            monomial += 1;
        }
        while monomial < 256 {
            hi |= (coeffs[monomial] as u128) << (monomial - 128);
            monomial += 1;
        }

        out[bit_idx][0] = lo;
        out[bit_idx][1] = hi;
        bit_idx += 1;
    }
    out
}

const SBOX1_ANF: [[u128; 2]; 8] = build_sbox_anf();

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

#[inline(always)]
fn sbox1(x: u8) -> u8 {
    SBOX1[x as usize]
}

#[inline(always)]
fn shl_256<const SHIFT: u32>(lo: u128, hi: u128) -> (u128, u128) {
    (lo << SHIFT, (hi << SHIFT) | (lo >> (128 - SHIFT)))
}

#[inline(always)]
fn subset_mask8(x: u8) -> (u128, u128) {
    let mut lo = 1u128;
    let mut hi = 0u128;

    let mask0 = 0u128.wrapping_sub((x & 1) as u128);
    let (add_lo, add_hi) = shl_256::<1>(lo, hi);
    lo |= add_lo & mask0;
    hi |= add_hi & mask0;

    let mask1 = 0u128.wrapping_sub(((x >> 1) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<2>(lo, hi);
    lo |= add_lo & mask1;
    hi |= add_hi & mask1;

    let mask2 = 0u128.wrapping_sub(((x >> 2) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<4>(lo, hi);
    lo |= add_lo & mask2;
    hi |= add_hi & mask2;

    let mask3 = 0u128.wrapping_sub(((x >> 3) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<8>(lo, hi);
    lo |= add_lo & mask3;
    hi |= add_hi & mask3;

    let mask4 = 0u128.wrapping_sub(((x >> 4) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<16>(lo, hi);
    lo |= add_lo & mask4;
    hi |= add_hi & mask4;

    let mask5 = 0u128.wrapping_sub(((x >> 5) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<32>(lo, hi);
    lo |= add_lo & mask5;
    hi |= add_hi & mask5;

    let mask6 = 0u128.wrapping_sub(((x >> 6) & 1) as u128);
    let (add_lo, add_hi) = shl_256::<64>(lo, hi);
    lo |= add_lo & mask6;
    hi |= add_hi & mask6;

    let mask7 = 0u128.wrapping_sub(((x >> 7) & 1) as u128);
    hi |= lo & mask7;

    (lo, hi)
}

#[inline(always)]
fn parity128(mut x: u128) -> u8 {
    x ^= x >> 64;
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0f;
    ((0x6996u16 >> (x as u16)) & 1) as u8
}

#[inline(always)]
fn sbox1_ct(x: u8) -> u8 {
    let (active_lo, active_hi) = subset_mask8(x);
    let mut out = 0u8;
    let mut bit_idx = 0usize;
    while bit_idx < 8 {
        let bit = parity128(active_lo & SBOX1_ANF[bit_idx][0])
            ^ parity128(active_hi & SBOX1_ANF[bit_idx][1]);
        out |= bit << bit_idx;
        bit_idx += 1;
    }
    out
}

#[inline(always)]
fn sbox2(x: u8) -> u8 {
    sbox1(x).rotate_left(1)
}

#[inline(always)]
fn sbox3(x: u8) -> u8 {
    sbox1(x).rotate_left(7)
}

#[inline(always)]
fn sbox4(x: u8) -> u8 {
    sbox1(x.rotate_left(1))
}

#[inline(always)]
fn sbox2_ct(x: u8) -> u8 {
    sbox1_ct(x).rotate_left(1)
}

#[inline(always)]
fn sbox3_ct(x: u8) -> u8 {
    sbox1_ct(x).rotate_left(7)
}

#[inline(always)]
fn sbox4_ct(x: u8) -> u8 {
    sbox1_ct(x.rotate_left(1))
}

#[inline(always)]
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

#[inline(always)]
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

#[inline(always)]
fn fl(x: u64, ke: u64) -> u64 {
    let mut x1 = (x >> 32) as u32;
    let mut x2 = x as u32;
    let k1 = (ke >> 32) as u32;
    let k2 = ke as u32;
    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;
    ((x1 as u64) << 32) | (x2 as u64)
}

#[inline(always)]
fn fl_inv(x: u64, ke: u64) -> u64 {
    let mut y1 = (x >> 32) as u32;
    let mut y2 = x as u32;
    let k1 = (ke >> 32) as u32;
    let k2 = ke as u32;
    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);
    ((y1 as u64) << 32) | (y2 as u64)
}

#[inline(always)]
fn halves(x: u128) -> (u64, u64) {
    ((x >> 64) as u64, x as u64)
}

#[inline(always)]
fn rot_pair(x: u128, bits: u32) -> (u64, u64) {
    halves(x.rotate_left(bits))
}

fn derive_ka(kl: u128, kr: u128, use_ct: bool) -> u128 {
    let x = kl ^ kr;
    let mut d1 = (x >> 64) as u64;
    let mut d2 = x as u64;
    let kl_l = (kl >> 64) as u64;
    let kl_r = kl as u64;

    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d2 ^= f(d1, SIGMA[0]);
    d1 ^= f(d2, SIGMA[1]);
    d1 ^= kl_l;
    d2 ^= kl_r;
    d2 ^= f(d1, SIGMA[2]);
    d1 ^= f(d2, SIGMA[3]);

    ((d1 as u128) << 64) | (d2 as u128)
}

fn derive_kb(ka: u128, kr: u128, use_ct: bool) -> u128 {
    let (kr_l, kr_r) = halves(kr);
    let (mut d1, mut d2) = halves(ka);

    let f = if use_ct { camellia_f_ct } else { camellia_f };

    d1 ^= kr_l;
    d2 ^= kr_r;
    d2 ^= f(d1, SIGMA[4]);
    d1 ^= f(d2, SIGMA[5]);

    ((d1 as u128) << 64) | (d2 as u128)
}

fn expand_128(key: &[u8; 16], use_ct: bool) -> Subkeys18 {
    let kl = u128::from_be_bytes(*key);
    let ka = derive_ka(kl, 0, use_ct);

    let kl0 = rot_pair(kl, 0);
    let kl15 = rot_pair(kl, 15);
    let kl45 = rot_pair(kl, 45);
    let kl60 = rot_pair(kl, 60);
    let kl77 = rot_pair(kl, 77);
    let kl94 = rot_pair(kl, 94);
    let kl111 = rot_pair(kl, 111);

    let ka0 = rot_pair(ka, 0);
    let ka15 = rot_pair(ka, 15);
    let ka30 = rot_pair(ka, 30);
    let ka45 = rot_pair(ka, 45);
    let ka60 = rot_pair(ka, 60);
    let ka94 = rot_pair(ka, 94);
    let ka111 = rot_pair(ka, 111);

    let mut out = Subkeys18 {
        kw: [0; 4],
        k: [0; 18],
        ke: [0; 4],
    };

    out.kw[0] = kl0.0;
    out.kw[1] = kl0.1;
    out.kw[2] = ka111.0;
    out.kw[3] = ka111.1;

    out.k[0] = ka0.0;
    out.k[1] = ka0.1;
    out.k[2] = kl15.0;
    out.k[3] = kl15.1;
    out.k[4] = ka15.0;
    out.k[5] = ka15.1;
    out.ke[0] = ka30.0;
    out.ke[1] = ka30.1;
    out.k[6] = kl45.0;
    out.k[7] = kl45.1;
    out.k[8] = ka45.0;
    out.k[9] = kl60.1;
    out.k[10] = ka60.0;
    out.k[11] = ka60.1;
    out.ke[2] = kl77.0;
    out.ke[3] = kl77.1;
    out.k[12] = kl94.0;
    out.k[13] = kl94.1;
    out.k[14] = ka94.0;
    out.k[15] = ka94.1;
    out.k[16] = kl111.0;
    out.k[17] = kl111.1;

    out
}

fn expand_192_256(kl: u128, kr: u128, use_ct: bool) -> Subkeys24 {
    let ka = derive_ka(kl, kr, use_ct);
    let kb = derive_kb(ka, kr, use_ct);

    let kl0 = rot_pair(kl, 0);
    let kl45 = rot_pair(kl, 45);
    let kl60 = rot_pair(kl, 60);
    let kl77 = rot_pair(kl, 77);
    let kl111 = rot_pair(kl, 111);

    let kr15 = rot_pair(kr, 15);
    let kr30 = rot_pair(kr, 30);
    let kr60 = rot_pair(kr, 60);
    let kr94 = rot_pair(kr, 94);

    let ka15 = rot_pair(ka, 15);
    let ka45 = rot_pair(ka, 45);
    let ka77 = rot_pair(ka, 77);
    let ka94 = rot_pair(ka, 94);

    let kb0 = rot_pair(kb, 0);
    let kb30 = rot_pair(kb, 30);
    let kb60 = rot_pair(kb, 60);
    let kb111 = rot_pair(kb, 111);

    let mut out = Subkeys24 {
        kw: [0; 4],
        k: [0; 24],
        ke: [0; 6],
    };

    out.kw[0] = kl0.0;
    out.kw[1] = kl0.1;
    out.kw[2] = kb111.0;
    out.kw[3] = kb111.1;

    out.k[0] = kb0.0;
    out.k[1] = kb0.1;
    out.k[2] = kr15.0;
    out.k[3] = kr15.1;
    out.k[4] = ka15.0;
    out.k[5] = ka15.1;
    out.ke[0] = kr30.0;
    out.ke[1] = kr30.1;
    out.k[6] = kb30.0;
    out.k[7] = kb30.1;
    out.k[8] = kl45.0;
    out.k[9] = kl45.1;
    out.k[10] = ka45.0;
    out.k[11] = ka45.1;
    out.ke[2] = kl60.0;
    out.ke[3] = kl60.1;
    out.k[12] = kr60.0;
    out.k[13] = kr60.1;
    out.k[14] = kb60.0;
    out.k[15] = kb60.1;
    out.k[16] = kl77.0;
    out.k[17] = kl77.1;
    out.ke[4] = ka77.0;
    out.ke[5] = ka77.1;
    out.k[18] = kr94.0;
    out.k[19] = kr94.1;
    out.k[20] = ka94.0;
    out.k[21] = ka94.1;
    out.k[22] = kl111.0;
    out.k[23] = kl111.1;

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

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_18(*block, &self.subkeys, false)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_18(*block, &self.subkeys, false)
    }
}

/// Camellia-128 constant-time software path.
pub struct Camellia128Ct {
    subkeys: Subkeys18,
}

impl Camellia128Ct {
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

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_18(*block, &self.subkeys, true)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_18(*block, &self.subkeys, true)
    }
}

/// Camellia-192 fast software path.
pub struct Camellia192 {
    subkeys: Subkeys24,
}

impl Camellia192 {
    pub fn new(key: &[u8; 24]) -> Self {
        let kl = u128::from_be_bytes(key[..16].try_into().unwrap());
        let tail = u64::from_be_bytes(key[16..].try_into().unwrap());
        let kr = ((tail as u128) << 64) | ((!tail) as u128);
        Self {
            subkeys: expand_192_256(kl, kr, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, false)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, false)
    }
}

/// Camellia-192 constant-time software path.
pub struct Camellia192Ct {
    subkeys: Subkeys24,
}

impl Camellia192Ct {
    pub fn new(key: &[u8; 24]) -> Self {
        let kl = u128::from_be_bytes(key[..16].try_into().unwrap());
        let tail = u64::from_be_bytes(key[16..].try_into().unwrap());
        let kr = ((tail as u128) << 64) | ((!tail) as u128);
        Self {
            subkeys: expand_192_256(kl, kr, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 24]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, true)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, true)
    }
}

/// Camellia-256 fast software path.
pub struct Camellia256 {
    subkeys: Subkeys24,
}

impl Camellia256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let kl = u128::from_be_bytes(key[..16].try_into().unwrap());
        let kr = u128::from_be_bytes(key[16..].try_into().unwrap());
        Self {
            subkeys: expand_192_256(kl, kr, false),
        }
    }

    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, false)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_decrypt_24(*block, &self.subkeys, false)
    }
}

/// Camellia-256 constant-time software path.
pub struct Camellia256Ct {
    subkeys: Subkeys24,
}

impl Camellia256Ct {
    pub fn new(key: &[u8; 32]) -> Self {
        let kl = u128::from_be_bytes(key[..16].try_into().unwrap());
        let kr = u128::from_be_bytes(key[16..].try_into().unwrap());
        Self {
            subkeys: expand_192_256(kl, kr, true),
        }
    }

    pub fn new_wiping(key: &mut [u8; 32]) -> Self {
        let out = Self::new(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        camellia_encrypt_24(*block, &self.subkeys, true)
    }

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
}
