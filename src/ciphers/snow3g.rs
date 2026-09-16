//! SNOW 3G stream cipher core, from ETSI/SAGE "Specification of the 3GPP
//! Confidentiality and Integrity Algorithms UEA2 & UIA2, Document 2: SNOW 3G
//! Specification", version 1.1 (6 September 2006).
//!
//! SNOW 3G is the 128-bit stream cipher used underneath 3GPP UEA2/UIA2. This
//! module implements the keystream generator of Document 2's normative
//! sections 3–5, not the higher-level UEA2/UIA2 framing. The test vectors come
//! from Document 3 of the same set, "Implementors' Test Data", version 1.1
//! (25 October 2012), section 3.

#[rustfmt::skip]
const SR: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

#[rustfmt::skip]
const SQ: [u8; 256] = [
    0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
    0xE4, 0x8E, 0x48, 0x49, 0x4F, 0x5D, 0x6A, 0x78, 0x70, 0x88, 0xE8, 0x5F, 0x5E, 0x84, 0x65, 0xE2,
    0xD8, 0xE9, 0xCC, 0xED, 0x40, 0x2F, 0x11, 0x28, 0x57, 0xD2, 0xAC, 0xE3, 0x4A, 0x15, 0x1B, 0xB9,
    0xB2, 0x80, 0x85, 0xA6, 0x2E, 0x02, 0x47, 0x29, 0x07, 0x4B, 0x0E, 0xC1, 0x51, 0xAA, 0x89, 0xD4,
    0xCA, 0x01, 0x46, 0xB3, 0xEF, 0xDD, 0x44, 0x7B, 0xC2, 0x7F, 0xBE, 0xC3, 0x9F, 0x20, 0x4C, 0x64,
    0x83, 0xA2, 0x68, 0x42, 0x13, 0xB4, 0x41, 0xCD, 0xBA, 0xC6, 0xBB, 0x6D, 0x4D, 0x71, 0x21, 0xF4,
    0x8D, 0xB0, 0xE5, 0x93, 0xFE, 0x8F, 0xE6, 0xCF, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xFA,
    0xBC, 0x0F, 0x08, 0x52, 0x1D, 0x55, 0x1A, 0xC5, 0x4E, 0x23, 0x69, 0x7A, 0x92, 0xFF, 0x5B, 0x5A,
    0xEB, 0x9A, 0x1C, 0xA9, 0xD1, 0x7E, 0x0D, 0xFC, 0x50, 0x8A, 0xB6, 0x62, 0xF5, 0x0A, 0xF8, 0xDC,
    0x03, 0x3C, 0x0C, 0x39, 0xF1, 0xB8, 0xF3, 0x3D, 0xF2, 0xD5, 0x97, 0x66, 0x81, 0x32, 0xA0, 0x00,
    0x06, 0xCE, 0xF6, 0xEA, 0xB7, 0x17, 0xF7, 0x8C, 0x79, 0xD6, 0xA7, 0xBF, 0x8B, 0x3F, 0x1F, 0x53,
    0x63, 0x75, 0x35, 0x2C, 0x60, 0xFD, 0x27, 0xD3, 0x94, 0xA5, 0x7C, 0xA1, 0x05, 0x58, 0x2D, 0xBD,
    0xD9, 0xC7, 0xAF, 0x6B, 0x54, 0x0B, 0xE0, 0x38, 0x04, 0xC8, 0x9D, 0xE7, 0x14, 0xB1, 0x87, 0x9C,
    0xDF, 0x6F, 0xF9, 0xDA, 0x2A, 0xC4, 0x59, 0x16, 0x74, 0x91, 0xAB, 0x26, 0x61, 0x76, 0x34, 0x2B,
    0xAD, 0x99, 0xFB, 0x72, 0xEC, 0x33, 0x12, 0xDE, 0x98, 0x3B, 0xC0, 0x9B, 0x3E, 0x18, 0x10, 0x3A,
    0x56, 0xE1, 0x77, 0xC9, 0x1E, 0x9E, 0x95, 0xA3, 0x90, 0x19, 0xA8, 0x6C, 0x09, 0xD0, 0xF0, 0x86,
];

const SR_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&SR);
const SQ_ANF: [[u128; 2]; 8] = crate::ct::build_byte_sbox_anf(&SQ);

// MULα and DIVα (Document 2 §3.4.2, §3.4.3) map a byte c to the word
// MULxPOW(c, e0, 0xA9) || MULxPOW(c, e1, 0xA9) || MULxPOW(c, e2, 0xA9) ||
// MULxPOW(c, e3, 0xA9), with exponents (23, 245, 48, 239) for MULα and
// (16, 39, 6, 64) for DIVα. The constant 0xA9 = 1010_1001 spells
// x^8 + x^7 + x^5 + x^3 + 1 (Annex 1 §1.5). The tables serve the fast path.
// Because MULxPOW(c, e, 0xA9) = c·β^e (Annex 1 §1.1), the constant-time path
// instead multiplies c by the factors β^e = MULxPOW(1, e, 0xA9) bit by bit.
const MUL_ALPHA: [u32; 256] = build_alpha_table([23, 245, 48, 239]);
const DIV_ALPHA: [u32; 256] = build_alpha_table([16, 39, 6, 64]);
const MUL_ALPHA_FACTORS: [u8; 4] = alpha_factors([23, 245, 48, 239]);
const DIV_ALPHA_FACTORS: [u8; 4] = alpha_factors([16, 39, 6, 64]);

// ── MULx and MULxPOW (Document 2 §3.1.1, §3.1.2) ─────────────────────────────

/// §3.1.1 `MULx(V, c)`: `V <<8 1`, XORed with `c` when the leftmost bit of `V`
/// is 1.
///
/// Branch-free: `v >> 7` is that leftmost bit and `0 - bit` is `0x00` or
/// `0xFF`, which gates `c`. Annex 1 §1.1 reads this as multiplication by the
/// root β of the polynomial whose low coefficients `c` spells.
#[inline]
const fn mul_x(v: u8, c: u8) -> u8 {
    (v << 1) ^ (c & 0u8.wrapping_sub(v >> 7))
}

/// §3.1.2 `MULxPOW(V, i, c)`: `V` when `i = 0`, otherwise
/// `MULx(MULxPOW(V, i - 1, c), c)` — the recursion unrolled into `i`
/// applications of `MULx`.
const fn mul_x_pow(v: u8, i: u8, c: u8) -> u8 {
    let mut acc = v;
    let mut remaining = i;
    while remaining > 0 {
        acc = mul_x(acc, c);
        remaining -= 1;
    }
    acc
}

// ── FSM S-boxes S1 and S2 (Document 2 §3.3.1, §3.3.2) ────────────────────────
//
// Both split w = w0 || w1 || w2 || w3 (w0 most significant), substitute each
// byte through an 8-bit S-box (SR for S1, SQ for S2), and mix the four results
// with MULx under a constant (0x1B for S1, 0x69 for S2). With a_i the
// substituted bytes and x_i = MULx(a_i, c), the tables in §3.3.1 and §3.3.2
// give the output bytes (r0 most significant) as
//
//     r0 = x0      ⊕ a1      ⊕ a2      ⊕ x3 ⊕ a3
//     r1 = x0 ⊕ a0 ⊕ x1      ⊕ a2      ⊕ a3
//     r2 = a0      ⊕ x1 ⊕ a1 ⊕ x2      ⊕ a3
//     r3 = a0      ⊕ a1      ⊕ x2 ⊕ a2 ⊕ x3

/// The byte mixing of §3.3.1 and §3.3.2, applied to the substituted bytes.
#[inline]
fn mix_substituted(a: [u8; 4], c: u8) -> u32 {
    let x = [
        mul_x(a[0], c),
        mul_x(a[1], c),
        mul_x(a[2], c),
        mul_x(a[3], c),
    ];
    u32::from_be_bytes([
        x[0] ^ a[1] ^ a[2] ^ x[3] ^ a[3],
        x[0] ^ a[0] ^ x[1] ^ a[2] ^ a[3],
        a[0] ^ x[1] ^ a[1] ^ x[2] ^ a[3],
        a[0] ^ a[1] ^ x[2] ^ a[2] ^ x[3],
    ])
}

/// §3.3.1 S-box S1: SR on each byte, mixed under `MULx(·, 0x1B)`.
///
/// With `CT`, SR is evaluated from its packed ANF instead of indexed.
#[inline]
fn fsm_s1<const CT: bool>(w: u32) -> u32 {
    let a = w.to_be_bytes().map(|byte| {
        if CT {
            sbox_eval(&SR_ANF, byte)
        } else {
            SR[usize::from(byte)]
        }
    });
    mix_substituted(a, 0x1B)
}

/// §3.3.2 S-box S2: SQ on each byte, mixed under `MULx(·, 0x69)`.
///
/// With `CT`, SQ is evaluated from its packed ANF instead of indexed.
#[inline]
fn fsm_s2<const CT: bool>(w: u32) -> u32 {
    let a = w.to_be_bytes().map(|byte| {
        if CT {
            sbox_eval(&SQ_ANF, byte)
        } else {
            SQ[usize::from(byte)]
        }
    });
    mix_substituted(a, 0x69)
}

// ── Clocking and operation (Document 2 §3.4, §4) ─────────────────────────────

/// §3.4.4 and §3.4.5: clock the LFSR once, feeding in `fsm_word`.
///
/// Initialisation Mode passes the FSM output F. Keystream Mode's `v` is the
/// same expression without the `⊕ F` term, so it passes 0.
///
/// In `v`, `(s0,1 || s0,2 || s0,3 || 0x00)` is `s0 << 8` and
/// `(0x00 || s11,0 || s11,1 || s11,2)` is `s11 >> 8`; the bytes those shifts
/// drop, `s0,0` and `s11,3`, are the inputs to MULα (§3.4.2) and DIVα
/// (§3.4.3).
#[inline]
fn lfsr_clock<const CT: bool>(core: &mut Snow3gCore, fsm_word: u32) {
    let s0 = core.s[0];
    let s11 = core.s[11];
    let s0_high = s0.to_be_bytes()[0];
    let s11_low = s11.to_be_bytes()[3];
    let (alpha_term, alpha_inverse_term) = if CT {
        (
            alpha_word_ct(s0_high, MUL_ALPHA_FACTORS),
            alpha_word_ct(s11_low, DIV_ALPHA_FACTORS),
        )
    } else {
        (
            MUL_ALPHA[usize::from(s0_high)],
            DIV_ALPHA[usize::from(s11_low)],
        )
    };
    let v = (s0 << 8) ^ alpha_term ^ core.s[2] ^ (s11 >> 8) ^ alpha_inverse_term ^ fsm_word;
    core.s.copy_within(1.., 0);
    core.s[15] = v;
}

/// §3.4.6: clock the FSM on `s15` and `s5` and return its output word F.
#[inline]
fn fsm_clock<const CT: bool>(core: &mut Snow3gCore) -> u32 {
    let f = core.s[15].wrapping_add(core.r1) ^ core.r2;
    let r = core.r2.wrapping_add(core.r3 ^ core.s[5]);
    core.r3 = fsm_s2::<CT>(core.r2);
    core.r2 = fsm_s1::<CT>(core.r1);
    core.r1 = r;
    f
}

/// The four 32-bit words of a 128-bit key or IV, most significant first
/// (§4.1's `k0..k3` and `IV0..IV3`, split as §2.2.2 numbers sub-strings).
fn be_words(bytes: &[u8; 16]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// §4.1 Initialisation, before the first clock: load the LFSR from the key
/// and IV words and zero the FSM registers.
fn load_key_iv(key: &[u8; 16], iv: &[u8; 16]) -> Snow3gCore {
    let mut k = be_words(key);
    let mut v = be_words(iv);
    // §4.1: "Let 1 be the all-ones word (0xffffffff)."
    let ones = u32::MAX;
    let core = Snow3gCore {
        ks: [0; 4],
        ks_len: 0,
        s: [
            k[0] ^ ones,
            k[1] ^ ones,
            k[2] ^ ones,
            k[3] ^ ones,
            k[0],
            k[1],
            k[2],
            k[3],
            k[0] ^ ones,
            k[1] ^ ones ^ v[3],
            k[2] ^ ones ^ v[2],
            k[3] ^ ones,
            k[0] ^ v[1],
            k[1],
            k[2],
            k[3] ^ v[0],
        ],
        r1: 0,
        r2: 0,
        r3: 0,
    };
    crate::ct::zeroize_slice(k.as_mut_slice());
    crate::ct::zeroize_slice(v.as_mut_slice());
    core
}

/// §4.1 and the start of §4.2: load key and IV, run the 32 initialisation
/// clocks, then clock the FSM once (output discarded) and the LFSR once in
/// Keystream Mode, so that the next `keystream_word` is `z1`.
fn initialise<const CT: bool>(key: &[u8; 16], iv: &[u8; 16]) -> Snow3gCore {
    let mut core = load_key_iv(key, iv);
    for _ in 0..32 {
        let f = fsm_clock::<CT>(&mut core);
        lfsr_clock::<CT>(&mut core, f);
    }
    let _ = fsm_clock::<CT>(&mut core);
    lfsr_clock::<CT>(&mut core, 0);
    core
}

/// One pass of the §4.2 loop: clock the FSM for F, output `z = F ⊕ s0`, and
/// clock the LFSR in Keystream Mode.
#[inline]
fn keystream_word<const CT: bool>(core: &mut Snow3gCore) -> u32 {
    let z = fsm_clock::<CT>(core) ^ core.s[0];
    lfsr_clock::<CT>(core, 0);
    z
}

const fn build_alpha_table(pows: [u8; 4]) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u8;
        table[i] = u32::from_be_bytes([
            mul_x_pow(c, pows[0], 0xA9),
            mul_x_pow(c, pows[1], 0xA9),
            mul_x_pow(c, pows[2], 0xA9),
            mul_x_pow(c, pows[3], 0xA9),
        ]);
        i += 1;
    }
    table
}

const fn alpha_factors(pows: [u8; 4]) -> [u8; 4] {
    [
        mul_x_pow(1, pows[0], 0xA9),
        mul_x_pow(1, pows[1], 0xA9),
        mul_x_pow(1, pows[2], 0xA9),
        mul_x_pow(1, pows[3], 0xA9),
    ]
}

#[inline]
fn gf_mul_const_ct(mut value: u8, mut factor: u8, poly: u8) -> u8 {
    let mut out = 0u8;
    let mut i = 0u8;
    while i < 8 {
        let bit_mask = 0u8.wrapping_sub(factor & 1);
        out ^= value & bit_mask;
        value = mul_x(value, poly);
        factor >>= 1;
        i = i.wrapping_add(1);
    }
    out
}

#[inline]
fn alpha_word_ct(input: u8, factors: [u8; 4]) -> u32 {
    u32::from_be_bytes([
        gf_mul_const_ct(input, factors[0], 0xA9),
        gf_mul_const_ct(input, factors[1], 0xA9),
        gf_mul_const_ct(input, factors[2], 0xA9),
        gf_mul_const_ct(input, factors[3], 0xA9),
    ])
}

#[inline]
fn sbox_eval(coeffs: &[[u128; 2]; 8], input: u8) -> u8 {
    crate::ct::eval_byte_sbox(coeffs, input)
}

struct Snow3gCore {
    /// Keystream bytes of a partially consumed word, right-aligned:
    /// `ks[4 - ks_len..]` are still unused.
    ks: [u8; 4],
    ks_len: u8,
    s: [u32; 16],
    r1: u32,
    r2: u32,
    r3: u32,
}

impl Snow3gCore {
    /// Forget the unused bytes of a partially consumed word. Unused keystream
    /// is as secret as the state that made it, so it is wiped, not just
    /// forgotten.
    fn discard_pending(&mut self) {
        crate::ct::zeroize_slice(self.ks.as_mut_slice());
        self.ks_len = 0;
    }
}

fn fill_core<const CT: bool>(core: &mut Snow3gCore, mut buf: &mut [u8]) {
    // Drain the unused bytes of the last partial word first, so a sequence
    // of `fill` calls sees one continuous keystream regardless of how the
    // caller chunks its buffers.
    let pending = usize::from(core.ks_len);
    if pending > 0 {
        let take = pending.min(buf.len());
        let start = 4 - pending;
        for (b, k) in buf[..take].iter_mut().zip(&core.ks[start..start + take]) {
            *b ^= k;
        }
        core.ks_len = u8::try_from(pending - take).expect("at most 3");
        buf = &mut buf[take..];
    }
    let mut chunks = buf.chunks_exact_mut(4);
    for chunk in &mut chunks {
        let ks = keystream_word::<CT>(core).to_be_bytes();
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let ks = keystream_word::<CT>(core).to_be_bytes();
        for (b, k) in rem.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        core.ks = ks;
        core.ks_len = u8::try_from(4 - rem.len()).expect("at most 3");
    }
}

/// SNOW 3G stream cipher (ETSI/SAGE Document 2, version 1.1).
///
/// **Not constant-time.** Every clock reads MULα and DIVα (§3.4.2, §3.4.3),
/// two 1 KiB tables, at indices that are bytes of the secret LFSR cells `s0`
/// and `s11`, and the FSM's S1 and S2 (§3.3) read the SR and SQ tables at
/// bytes of the secret registers R1 and R2. The memory access pattern
/// therefore depends on the key. Where an attacker may observe timing or
/// cache behaviour, use [`Snow3gCt`], which computes the same keystream
/// without secret-indexed reads.
pub struct Snow3g {
    core: Snow3gCore,
}

/// SNOW 3G constant-time software path.
///
/// `Snow3gCt` runs the same LFSR and FSM as [`Snow3g`] but never indexes a
/// table with secret data: SR and SQ are evaluated from their packed ANF, and
/// MULα and DIVα multiply by their constant GF(2^8) factors bit by bit.
pub struct Snow3gCt {
    core: Snow3gCore,
}

impl Snow3g {
    /// Construct SNOW 3G from a 128-bit key and 128-bit IV.
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            core: initialise::<false>(key, iv),
        }
    }

    /// Construct and wipe the caller-provided key and IV buffers.
    pub fn new_wiping(key: &mut [u8; 16], iv: &mut [u8; 16]) -> Self {
        let out = Self::new(key, iv);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(iv.as_mut_slice());
        out
    }

    /// Generate the next 32-bit keystream word.
    ///
    /// Starts a fresh word: any bytes left over from a partial-word `fill` are
    /// discarded (and wiped).
    pub fn next_word(&mut self) -> u32 {
        self.core.discard_pending();
        keystream_word::<false>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes in big-endian word order.
    ///
    /// Successive calls continue the same keystream byte for byte: a partially
    /// consumed word is carried over, so chunked and one-shot encryption of the
    /// same data agree.
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<false>(&mut self.core, buf);
    }
}

impl Snow3gCt {
    /// Construct SNOW 3G constant-time software path from a 128-bit key and IV.
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            core: initialise::<true>(key, iv),
        }
    }

    /// Construct and wipe the caller-provided key and IV buffers.
    pub fn new_wiping(key: &mut [u8; 16], iv: &mut [u8; 16]) -> Self {
        let out = Self::new(key, iv);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(iv.as_mut_slice());
        out
    }

    /// Generate the next 32-bit keystream word.
    ///
    /// Starts a fresh word: any bytes left over from a partial-word `fill` are
    /// discarded (and wiped).
    pub fn next_word(&mut self) -> u32 {
        self.core.discard_pending();
        keystream_word::<true>(&mut self.core)
    }

    /// XOR `buf` with keystream bytes in big-endian word order.
    ///
    /// Successive calls continue the same keystream byte for byte: a partially
    /// consumed word is carried over, so chunked and one-shot encryption of the
    /// same data agree.
    pub fn fill(&mut self, buf: &mut [u8]) {
        fill_core::<true>(&mut self.core, buf);
    }
}

impl Drop for Snow3g {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        crate::ct::zeroize_slice(self.core.ks.as_mut_slice());
        self.core.ks_len = 0;
        self.core.r1 = 0;
        self.core.r2 = 0;
        self.core.r3 = 0;
    }
}

impl Drop for Snow3gCt {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.s.as_mut_slice());
        crate::ct::zeroize_slice(self.core.ks.as_mut_slice());
        self.core.ks_len = 0;
        self.core.r1 = 0;
        self.core.r2 = 0;
        self.core.r3 = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keystream is one continuous byte stream: chunked fills must agree
    /// with a single fill regardless of where the chunk boundaries fall
    /// relative to the 32-bit word boundaries.
    #[test]
    fn chunked_fill_matches_one_shot() {
        let key = [0x5Au8; 16];
        let iv = [0xA5u8; 16];
        let mut one_shot = [0u8; 29];
        let mut chunked = [0u8; 29];
        Snow3g::new(&key, &iv).fill(&mut one_shot);
        let mut z = Snow3g::new(&key, &iv);
        let mut off = 0;
        for len in [1usize, 3, 7, 4, 9, 5] {
            z.fill(&mut chunked[off..off + len]);
            off += len;
        }
        assert_eq!(chunked, one_shot);

        let mut one_shot_ct = [0u8; 29];
        let mut chunked_ct = [0u8; 29];
        Snow3gCt::new(&key, &iv).fill(&mut one_shot_ct);
        let mut z = Snow3gCt::new(&key, &iv);
        let mut off = 0;
        for len in [1usize, 3, 7, 4, 9, 5] {
            z.fill(&mut chunked_ct[off..off + len]);
            off += len;
        }
        assert_eq!(chunked_ct, one_shot_ct);
        assert_eq!(one_shot_ct, one_shot);
    }

    /// Fills shorter than the pending remainder of a word: one word is
    /// consumed a byte (or three, then one) at a time, so a partial word is
    /// carried across several calls and drained from successive offsets.
    #[test]
    fn sub_word_fills_drain_one_pending_word_across_calls() {
        let key = [0x5Au8; 16];
        let iv = [0xA5u8; 16];
        let mut one_shot = [0u8; 12];
        Snow3g::new(&key, &iv).fill(&mut one_shot);
        let mut one_shot_ct = [0u8; 12];
        Snow3gCt::new(&key, &iv).fill(&mut one_shot_ct);
        assert_eq!(one_shot_ct, one_shot);

        for lens in [
            [1usize; 12].as_slice(),
            &[3, 1, 1, 1, 2, 1, 1, 2],
            &[2, 1, 1, 3, 3, 2],
        ] {
            let mut chunked = [0u8; 12];
            let mut snow = Snow3g::new(&key, &iv);
            let mut off = 0;
            for &len in lens {
                snow.fill(&mut chunked[off..off + len]);
                off += len;
            }
            assert_eq!(off, 12);
            assert_eq!(chunked, one_shot, "chunking {lens:?}");

            let mut chunked_ct = [0u8; 12];
            let mut snow = Snow3gCt::new(&key, &iv);
            let mut off = 0;
            for &len in lens {
                snow.fill(&mut chunked_ct[off..off + len]);
                off += len;
            }
            assert_eq!(chunked_ct, one_shot, "chunking {lens:?} (ct)");
        }
    }

    /// `next_word` after a partial-word `fill` starts a fresh word and leaves
    /// no pending keystream bytes behind.
    #[test]
    fn next_word_discards_and_wipes_pending_bytes() {
        let key = [0x5Au8; 16];
        let iv = [0xA5u8; 16];
        let mut reference = Snow3g::new(&key, &iv);
        let _ = reference.next_word();
        let second = reference.next_word();

        let mut snow = Snow3g::new(&key, &iv);
        snow.fill(&mut [0u8; 1]);
        assert_eq!(snow.core.ks_len, 3);
        assert_eq!(snow.next_word(), second);
        assert_eq!(snow.core.ks_len, 0);
        assert_eq!(snow.core.ks, [0u8; 4]);

        let mut snow = Snow3gCt::new(&key, &iv);
        snow.fill(&mut [0u8; 1]);
        assert_eq!(snow.next_word(), second);
        assert_eq!(snow.core.ks_len, 0);
        assert_eq!(snow.core.ks, [0u8; 4]);
    }

    /// `new_wiping` zeroes the caller's key and IV and yields the same stream
    /// as `new`, on both paths.
    #[test]
    fn new_wiping_zeroes_inputs_and_matches_new() {
        let key: [u8; 16] = core::array::from_fn(|i| u8::try_from(i * 9).expect("< 144"));
        let iv: [u8; 16] = core::array::from_fn(|i| u8::try_from(i * 13).expect("< 208"));

        let mut expected = [0u8; 40];
        Snow3g::new(&key, &iv).fill(&mut expected);
        let mut key_buf = key;
        let mut iv_buf = iv;
        let mut snow = Snow3g::new_wiping(&mut key_buf, &mut iv_buf);
        assert_eq!(key_buf, [0u8; 16]);
        assert_eq!(iv_buf, [0u8; 16]);
        let mut out = [0u8; 40];
        snow.fill(&mut out);
        assert_eq!(out, expected);

        let mut expected_ct = [0u8; 40];
        Snow3gCt::new(&key, &iv).fill(&mut expected_ct);
        assert_eq!(expected_ct, expected);
        let mut key_buf = key;
        let mut iv_buf = iv;
        let mut snow = Snow3gCt::new_wiping(&mut key_buf, &mut iv_buf);
        assert_eq!(key_buf, [0u8; 16]);
        assert_eq!(iv_buf, [0u8; 16]);
        let mut out = [0u8; 40];
        snow.fill(&mut out);
        assert_eq!(out, expected_ct);
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn fill_bytes(state: &mut u64, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = xorshift64(state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TraceRow {
        s0: u32,
        s2: u32,
        s5: u32,
        s11: u32,
        s15: u32,
        r1: u32,
        r2: u32,
        r3: u32,
    }

    fn trace_row(core: &Snow3gCore) -> TraceRow {
        TraceRow {
            s0: core.s[0],
            s2: core.s[2],
            s5: core.s[5],
            s11: core.s[11],
            s15: core.s[15],
            r1: core.r1,
            r2: core.r2,
            r3: core.r3,
        }
    }

    fn full_state(core: &Snow3gCore) -> ([u32; 16], [u32; 3]) {
        (core.s, [core.r1, core.r2, core.r3])
    }

    #[derive(Clone, Copy)]
    struct OfficialTraceCase {
        key: [u8; 16],
        iv: [u8; 16],
        initial_lfsr: [u32; 16],
        init_rows: [TraceRow; 8],
        final_lfsr: [u32; 16],
        final_fsm: [u32; 3],
        keystream_rows: [TraceRow; 3],
        outputs: [u32; 2],
    }

    /// Step the production key loading and clocks alongside Document 3's
    /// trace, then check that `initialise` lands on the same state as the
    /// stepped trace does.
    fn assert_official_trace<const CT: bool>(case: &OfficialTraceCase) {
        let mut core = load_key_iv(&case.key, &case.iv);
        assert_eq!(core.s, case.initial_lfsr, "initial LFSR (§4.1 loading)");
        assert_eq!([core.r1, core.r2, core.r3], [0; 3], "initial FSM");

        assert_eq!(trace_row(&core), case.init_rows[0], "initial row");
        for (i, expected) in case.init_rows.iter().enumerate().skip(1) {
            let f = fsm_clock::<CT>(&mut core);
            lfsr_clock::<CT>(&mut core, f);
            assert_eq!(trace_row(&core), *expected, "init row {i}");
        }

        for _ in (case.init_rows.len() - 1)..32 {
            let f = fsm_clock::<CT>(&mut core);
            lfsr_clock::<CT>(&mut core, f);
        }

        assert_eq!(core.s, case.final_lfsr, "final LFSR after init");
        assert_eq!(
            [core.r1, core.r2, core.r3],
            case.final_fsm,
            "final FSM after init"
        );

        let _ = fsm_clock::<CT>(&mut core);
        lfsr_clock::<CT>(&mut core, 0);
        assert_eq!(trace_row(&core), case.keystream_rows[0], "keystream row 0");
        assert_eq!(
            full_state(&initialise::<CT>(&case.key, &case.iv)),
            full_state(&core),
            "initialise() ends where the traced initialisation ends"
        );

        let z1 = keystream_word::<CT>(&mut core);
        assert_eq!(z1, case.outputs[0], "z1");
        assert_eq!(trace_row(&core), case.keystream_rows[1], "keystream row 1");

        let z2 = keystream_word::<CT>(&mut core);
        assert_eq!(z2, case.outputs[1], "z2");
        assert_eq!(trace_row(&core), case.keystream_rows[2], "keystream row 2");
    }

    fn assert_iterated_test_set_4<const CT: bool>() {
        let key = [
            0x0D, 0xED, 0x72, 0x63, 0x10, 0x9C, 0xF9, 0x2E, 0x33, 0x52, 0x25, 0x5A, 0x14, 0x0E,
            0x0F, 0x76,
        ];
        let iv = [
            0x6B, 0x68, 0x07, 0x9A, 0x41, 0xA7, 0xC4, 0xC9, 0x1B, 0xEF, 0xD7, 0x9F, 0x7F, 0xDC,
            0xC2, 0x33,
        ];

        let mut core = initialise::<CT>(&key, &iv);
        assert_eq!(keystream_word::<CT>(&mut core), 0xD712_C05C, "z1");
        assert_eq!(keystream_word::<CT>(&mut core), 0xA937_C2A6, "z2");
        assert_eq!(keystream_word::<CT>(&mut core), 0xEB7E_AAE3, "z3");
        for _ in 0..2496 {
            let _ = keystream_word::<CT>(&mut core);
        }
        assert_eq!(keystream_word::<CT>(&mut core), 0x9C0D_B3AA, "z2500");
    }

    /// Document 3 §3.3, Test Set 1: z1 and z2.
    #[test]
    fn keystream_test_set_1() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let iv = [
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xDF, 0x1F, 0x9B, 0x25, 0x1C, 0x0B,
            0xF4, 0x5F,
        ];
        let mut snow = Snow3g::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xABEE_9704);
        assert_eq!(snow.next_word(), 0x7AC3_1373);
    }

    /// Document 3 §3.4, Test Set 2: z1 and z2.
    #[test]
    fn keystream_test_set_2() {
        let key = [
            0x8C, 0xE3, 0x3E, 0x2C, 0xC3, 0xC0, 0xB5, 0xFC, 0x1F, 0x3D, 0xE8, 0xA6, 0xDC, 0x66,
            0xB1, 0xF3,
        ];
        let iv = [
            0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C, 0xDE, 0x55, 0x19, 0x88, 0xCE, 0xB2,
            0xF9, 0xB7,
        ];
        let mut snow = Snow3g::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xEFF8_A342);
        assert_eq!(snow.next_word(), 0xF751_480F);
    }

    /// Document 3 §3.5, Test Set 3: z1 and z2.
    #[test]
    fn keystream_test_set_3() {
        let key = [
            0x40, 0x35, 0xC6, 0x68, 0x0A, 0xF8, 0xC6, 0xD1, 0xA8, 0xFF, 0x86, 0x67, 0xB1, 0x71,
            0x40, 0x13,
        ];
        let iv = [
            0x62, 0xA5, 0x40, 0x98, 0x1B, 0xA6, 0xF9, 0xB7, 0x45, 0x92, 0xB0, 0xE7, 0x86, 0x90,
            0xF7, 0x1B,
        ];
        let mut snow = Snow3g::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xA8C8_74A9);
        assert_eq!(snow.next_word(), 0x7AE7_C4F8);
    }

    /// Document 3 §3.3, Test Set 1: z1 and z2, through the constant-time path.
    #[test]
    fn keystream_test_set_1_ct() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let iv = [
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xDF, 0x1F, 0x9B, 0x25, 0x1C, 0x0B,
            0xF4, 0x5F,
        ];
        let mut snow = Snow3gCt::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xABEE_9704);
        assert_eq!(snow.next_word(), 0x7AC3_1373);
    }

    /// Document 3 §3.4, Test Set 2: z1 and z2, through the constant-time path.
    #[test]
    fn keystream_test_set_2_ct() {
        let key = [
            0x8C, 0xE3, 0x3E, 0x2C, 0xC3, 0xC0, 0xB5, 0xFC, 0x1F, 0x3D, 0xE8, 0xA6, 0xDC, 0x66,
            0xB1, 0xF3,
        ];
        let iv = [
            0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C, 0xDE, 0x55, 0x19, 0x88, 0xCE, 0xB2,
            0xF9, 0xB7,
        ];
        let mut snow = Snow3gCt::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xEFF8_A342);
        assert_eq!(snow.next_word(), 0xF751_480F);
    }

    /// Document 3 §3.5, Test Set 3: z1 and z2, through the constant-time path.
    #[test]
    fn keystream_test_set_3_ct() {
        let key = [
            0x40, 0x35, 0xC6, 0x68, 0x0A, 0xF8, 0xC6, 0xD1, 0xA8, 0xFF, 0x86, 0x67, 0xB1, 0x71,
            0x40, 0x13,
        ];
        let iv = [
            0x62, 0xA5, 0x40, 0x98, 0x1B, 0xA6, 0xF9, 0xB7, 0x45, 0x92, 0xB0, 0xE7, 0x86, 0x90,
            0xF7, 0x1B,
        ];
        let mut snow = Snow3gCt::new(&key, &iv);
        assert_eq!(snow.next_word(), 0xA8C8_74A9);
        assert_eq!(snow.next_word(), 0x7AE7_C4F8);
    }

    #[test]
    fn fill_xor_roundtrip() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = b"Hello, SNOW 3G!!";
        let mut buf = *plaintext;
        Snow3g::new(&key, &iv).fill(&mut buf);
        Snow3g::new(&key, &iv).fill(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn fill_partial_word() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut buf7 = [0u8; 7];
        let mut buf8 = [0u8; 8];
        Snow3g::new(&key, &iv).fill(&mut buf7);
        Snow3g::new(&key, &iv).fill(&mut buf8);
        assert_eq!(buf7[..], buf8[..7]);
    }

    #[test]
    fn fill_xor_roundtrip_ct() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = b"Hello, SNOW 3G!!";
        let mut buf = *plaintext;
        Snow3gCt::new(&key, &iv).fill(&mut buf);
        Snow3gCt::new(&key, &iv).fill(&mut buf);
        assert_eq!(&buf, plaintext);
    }

    #[test]
    fn fill_partial_word_ct() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut buf7 = [0u8; 7];
        let mut buf8 = [0u8; 8];
        Snow3gCt::new(&key, &iv).fill(&mut buf7);
        Snow3gCt::new(&key, &iv).fill(&mut buf8);
        assert_eq!(buf7[..], buf8[..7]);
    }

    #[test]
    fn ct_sboxes_match_tables() {
        for x in 0u16..=255 {
            let b = u8::try_from(x).expect("table index fits in u8");
            assert_eq!(sbox_eval(&SR_ANF, b), SR[x as usize], "SR {x:02x}");
            assert_eq!(sbox_eval(&SQ_ANF, b), SQ[x as usize], "SQ {x:02x}");
            assert_eq!(
                alpha_word_ct(b, MUL_ALPHA_FACTORS),
                MUL_ALPHA[x as usize],
                "MUL {x:02x}"
            );
            assert_eq!(
                alpha_word_ct(b, DIV_ALPHA_FACTORS),
                DIV_ALPHA[x as usize],
                "DIV {x:02x}"
            );
        }
    }

    #[test]
    fn snow3g_and_ct_match() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let mut fast = Snow3g::new(&key, &iv);
        let mut slow = Snow3gCt::new(&key, &iv);
        for _ in 0..4 {
            assert_eq!(fast.next_word(), slow.next_word());
        }
    }

    #[test]
    fn snow3g_and_ct_match_random_streams() {
        let mut seed = 0xfeed_face_cafe_beefu64;
        for _ in 0..128 {
            let mut key = [0u8; 16];
            let mut iv = [0u8; 16];
            fill_bytes(&mut seed, &mut key);
            fill_bytes(&mut seed, &mut iv);
            let len = (xorshift64(&mut seed) as usize % 2048) + 1;

            let mut fast_buf = vec![0u8; len];
            let mut ct_buf = vec![0u8; len];
            fill_bytes(&mut seed, &mut fast_buf);
            ct_buf.copy_from_slice(&fast_buf);

            Snow3g::new(&key, &iv).fill(&mut fast_buf);
            Snow3gCt::new(&key, &iv).fill(&mut ct_buf);
            assert_eq!(fast_buf, ct_buf);
        }
    }

    /// Document 3 §3.3, Test Set 1: the initial LFSR, the first 8 initialisation
    /// steps, the state after initialisation, the first 3 keystream steps, and
    /// z1, z2, through both paths.
    #[test]
    fn official_test_set_1_trace_fast_and_ct() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let iv = [
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84, 0xDF, 0x1F, 0x9B, 0x25, 0x1C, 0x0B,
            0xF4, 0x5F,
        ];
        let initial_lfsr = [
            0xD429_BA60,
            0x7D3A_4CFF,
            0x6AD3_B6EF,
            0xB77E_00B7,
            0x2BD6_459F,
            0x82C5_B300,
            0x952C_4910,
            0x4881_FF48,
            0xD429_BA60,
            0x6131_B8A0,
            0xB5CC_2DCA,
            0xB77E_00B7,
            0x868A_081B,
            0x82C5_B300,
            0x952C_4910,
            0xA283_B85C,
        ];
        let init_rows = [
            TraceRow {
                s0: 0xD429_BA60,
                s2: 0x6AD3_B6EF,
                s5: 0x82C5_B300,
                s11: 0xB77E_00B7,
                s15: 0xA283_B85C,
                r1: 0x0000_0000,
                r2: 0x0000_0000,
                r3: 0x0000_0000,
            },
            TraceRow {
                s0: 0x7D3A_4CFF,
                s2: 0xB77E_00B7,
                s5: 0x952C_4910,
                s11: 0x868A_081B,
                s15: 0x97DF_2884,
                r1: 0x82C5_B300,
                r2: 0x6363_6363,
                r3: 0x2525_2525,
            },
            TraceRow {
                s0: 0x6AD3_B6EF,
                s2: 0x2BD6_459F,
                s5: 0x4881_FF48,
                s11: 0x82C5_B300,
                s15: 0x311B_A301,
                r1: 0x136C_CF98,
                r2: 0x486C_5BC4,
                r3: 0x9393_9393,
            },
            TraceRow {
                s0: 0xB77E_00B7,
                s2: 0x82C5_B300,
                s5: 0xD429_BA60,
                s11: 0x952C_4910,
                s15: 0xA69F_CBCB,
                r1: 0x237E_C89F,
                r2: 0xEAEB_C424,
                r3: 0x4B78_15EA,
            },
            TraceRow {
                s0: 0x2BD6_459F,
                s2: 0x952C_4910,
                s5: 0x6131_B8A0,
                s11: 0xA283_B85C,
                s15: 0xE76F_0ADA,
                r1: 0x8A3D_73AE,
                r2: 0x21A4_385B,
                r3: 0xE662_EC27,
            },
            TraceRow {
                s0: 0x82C5_B300,
                s2: 0x4881_FF48,
                s5: 0xB5CC_2DCA,
                s11: 0x97DF_2884,
                s15: 0xA52D_CD12,
                r1: 0xA8F7_8CE2,
                r2: 0x63A7_F600,
                r3: 0xBC3F_3A8D,
            },
            TraceRow {
                s0: 0x952C_4910,
                s2: 0xD429_BA60,
                s5: 0xB77E_00B7,
                s11: 0x311B_A301,
                s15: 0x1A34_9A62,
                r1: 0x6D9B_0D47,
                r2: 0x2071_2A2D,
                r3: 0x391D_0883,
            },
            TraceRow {
                s0: 0x4881_FF48,
                s2: 0x6131_B8A0,
                s5: 0x868A_081B,
                s11: 0xA69F_CBCB,
                s15: 0x2A2A_44DB,
                r1: 0xAED4_3261,
                r2: 0x401B_1511,
                r3: 0x45A6_ED60,
            },
        ];
        let final_lfsr = [
            0x8F12_15A6,
            0xE003_A052,
            0x9241_C929,
            0x68D7_BF8C,
            0x16BF_4C2A,
            0x8DEF_9D70,
            0x3238_1704,
            0x11DD_346A,
            0xE18B_81EA,
            0x77EB_D4FE,
            0x57ED_9505,
            0x0C33_C0EF,
            0x1A03_7B59,
            0x9759_1E82,
            0xA91C_CB44,
            0x7B48_E04F,
        ];
        let final_fsm = [0x61DA_9249, 0x427D_F38C, 0x0FB6_B101];
        let keystream_rows = [
            TraceRow {
                s0: 0xE003_A052,
                s2: 0x68D7_BF8C,
                s5: 0x3238_1704,
                s11: 0x1A03_7B59,
                s15: 0x1646_644C,
                r1: 0xC4D7_1FFD,
                r2: 0x90F0_B31F,
                r3: 0xCC61_2008,
            },
            TraceRow {
                s0: 0x9241_C929,
                s2: 0x16BF_4C2A,
                s5: 0x11DD_346A,
                s11: 0x9759_1E82,
                s15: 0x52E4_3190,
                r1: 0x8F49_EA2B,
                r2: 0x0AAC_C1E1,
                r3: 0x3367_438C,
            },
            TraceRow {
                s0: 0x68D7_BF8C,
                s2: 0x8DEF_9D70,
                s5: 0xE18B_81EA,
                s11: 0xA91C_CB44,
                s15: 0xB737_110E,
                r1: 0x2D67_39C7,
                r2: 0x5295_DA23,
                r3: 0x5293_E49E,
            },
        ];
        let outputs = [0xABEE_9704, 0x7AC3_1373];

        let case = OfficialTraceCase {
            key,
            iv,
            initial_lfsr,
            init_rows,
            final_lfsr,
            final_fsm,
            keystream_rows,
            outputs,
        };
        assert_official_trace::<false>(&case);
        assert_official_trace::<true>(&case);
    }

    /// Document 3 §3.4, Test Set 2: the same trace points as Test Set 1.
    #[test]
    fn official_test_set_2_trace_fast_and_ct() {
        let key = [
            0x8C, 0xE3, 0x3E, 0x2C, 0xC3, 0xC0, 0xB5, 0xFC, 0x1F, 0x3D, 0xE8, 0xA6, 0xDC, 0x66,
            0xB1, 0xF3,
        ];
        let iv = [
            0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C, 0xDE, 0x55, 0x19, 0x88, 0xCE, 0xB2,
            0xF9, 0xB7,
        ];
        let initial_lfsr = [
            0x731C_C1D3,
            0x3C3F_4A03,
            0xE0C2_1759,
            0x2399_4E0C,
            0x8CE3_3E2C,
            0xC3C0_B5FC,
            0x1F3D_E8A6,
            0xDC66_B1F3,
            0x731C_C1D3,
            0xF28D_B3B4,
            0x3E97_0ED1,
            0x2399_4E0C,
            0xBE9C_8F30,
            0xC3C0_B5FC,
            0x1F3D_E8A6,
            0x0FA3_6461,
        ];
        let init_rows = [
            TraceRow {
                s0: 0x731C_C1D3,
                s2: 0xE0C2_1759,
                s5: 0xC3C0_B5FC,
                s11: 0x2399_4E0C,
                s15: 0x0FA3_6461,
                r1: 0x0000_0000,
                r2: 0x0000_0000,
                r3: 0x0000_0000,
            },
            TraceRow {
                s0: 0x3C3F_4A03,
                s2: 0x2399_4E0C,
                s5: 0x1F3D_E8A6,
                s11: 0xBE9C_8F30,
                s15: 0xEF81_E474,
                r1: 0xC3C0_B5FC,
                r2: 0x6363_6363,
                r3: 0x2525_2525,
            },
            TraceRow {
                s0: 0xE0C2_1759,
                s2: 0x8CE3_3E2C,
                s5: 0xDC66_B1F3,
                s11: 0xC3C0_B5FC,
                s15: 0x7A55_4815,
                r1: 0x9D7C_30E6,
                r2: 0xF878_FA8B,
                r3: 0x9393_9393,
            },
            TraceRow {
                s0: 0x2399_4E0C,
                s2: 0xC3C0_B5FC,
                s5: 0x731C_C1D3,
                s11: 0x1F3D_E8A6,
                s15: 0x53E0_AE66,
                r1: 0x486E_1CEB,
                r2: 0x2148_E845,
                r3: 0x098F_198B,
            },
            TraceRow {
                s0: 0x8CE3_3E2C,
                s2: 0x1F3D_E8A6,
                s5: 0xF28D_B3B4,
                s11: 0x0FA3_6461,
                s15: 0x9A1E_E9B8,
                r1: 0x9BDC_C09D,
                r2: 0x87A6_22BB,
                r3: 0xEFFA_4239,
            },
            TraceRow {
                s0: 0xC3C0_B5FC,
                s2: 0xDC66_B1F3,
                s5: 0x3E97_0ED1,
                s11: 0xEF81_E474,
                s15: 0x2390_FE04,
                r1: 0xA51E_1448,
                r2: 0xF6CF_B4FB,
                r3: 0x2087_DC1D,
            },
            TraceRow {
                s0: 0x1F3D_E8A6,
                s2: 0x731C_C1D3,
                s5: 0x2399_4E0C,
                s11: 0x7A55_4815,
                s15: 0x6FB8_C36C,
                r1: 0x14E0_87C7,
                r2: 0x7246_2DC5,
                r3: 0x0B8B_F471,
            },
            TraceRow {
                s0: 0xDC66_B1F3,
                s2: 0xF28D_B3B4,
                s5: 0xBE9C_8F30,
                s11: 0x53E0_AE66,
                s15: 0xBA5D_B98F,
                r1: 0x9A58_E842,
                r2: 0x481D_2AB5,
                r3: 0x5C8E_E565,
            },
        ];
        let final_lfsr = [
            0x04D6_A929,
            0x942E_1440,
            0x82AB_D3FE,
            0x5832_E9F4,
            0x5F97_02A0,
            0x0871_2C81,
            0x644C_C9B9,
            0xDBF6_DE13,
            0xBAA5_B1D0,
            0x92E9_DD53,
            0xA2E2_FA6D,
            0xCE69_65AA,
            0x02C0_CD4E,
            0x6E6D_984F,
            0x114A_90E7,
            0x5279_F8DA,
        ];
        let final_fsm = [0x6513_0120, 0xA14C_7DBD, 0xB68B_551A];
        let keystream_rows = [
            TraceRow {
                s0: 0x942E_1440,
                s2: 0x5832_E9F4,
                s5: 0x644C_C9B9,
                s11: 0x02C0_CD4E,
                s15: 0xC1E9_3B6B,
                r1: 0x6046_F758,
                r2: 0x59E6_85C1,
                r3: 0x7DCB_C989,
            },
            TraceRow {
                s0: 0x82AB_D3FE,
                s2: 0x5F97_02A0,
                s5: 0xDBF6_DE13,
                s11: 0x6E6D_984F,
                s15: 0xCEB9_9926,
                r1: 0x736D_85F1,
                r2: 0x37DD_84E6,
                r3: 0xA9BE_CBB1,
            },
            TraceRow {
                s0: 0x5832_E9F4,
                s2: 0x0871_2C81,
                s5: 0xBAA5_B1D0,
                s11: 0x114A_90E7,
                s15: 0xE34F_6919,
                r1: 0xAA25_9A88,
                r2: 0x56C4_5F48,
                r3: 0xC354_6A61,
            },
        ];
        let outputs = [0xEFF8_A342, 0xF751_480F];

        let case = OfficialTraceCase {
            key,
            iv,
            initial_lfsr,
            init_rows,
            final_lfsr,
            final_fsm,
            keystream_rows,
            outputs,
        };
        assert_official_trace::<false>(&case);
        assert_official_trace::<true>(&case);
    }

    /// Document 3 §3.5, Test Set 3: the same trace points as Test Set 1.
    #[test]
    fn official_test_set_3_trace_fast_and_ct() {
        let key = [
            0x40, 0x35, 0xC6, 0x68, 0x0A, 0xF8, 0xC6, 0xD1, 0xA8, 0xFF, 0x86, 0x67, 0xB1, 0x71,
            0x40, 0x13,
        ];
        let iv = [
            0x62, 0xA5, 0x40, 0x98, 0x1B, 0xA6, 0xF9, 0xB7, 0x45, 0x92, 0xB0, 0xE7, 0x86, 0x90,
            0xF7, 0x1B,
        ];
        let initial_lfsr = [
            0xBFCA_3997,
            0xF507_392E,
            0x5700_7998,
            0x4E8E_BFEC,
            0x4035_C668,
            0x0AF8_C6D1,
            0xA8FF_8667,
            0xB171_4013,
            0xBFCA_3997,
            0x7397_CE35,
            0x1292_C97F,
            0x4E8E_BFEC,
            0x5B93_3FDF,
            0x0AF8_C6D1,
            0xA8FF_8667,
            0xD3D4_008B,
        ];
        let init_rows = [
            TraceRow {
                s0: 0xBFCA_3997,
                s2: 0x5700_7998,
                s5: 0x0AF8_C6D1,
                s11: 0x4E8E_BFEC,
                s15: 0xD3D4_008B,
                r1: 0x0000_0000,
                r2: 0x0000_0000,
                r3: 0x0000_0000,
            },
            TraceRow {
                s0: 0xF507_392E,
                s2: 0x4E8E_BFEC,
                s5: 0xA8FF_8667,
                s11: 0x5B93_3FDF,
                s15: 0xEE2C_ABF5,
                r1: 0x0AF8_C6D1,
                r2: 0x6363_6363,
                r3: 0x2525_2525,
            },
            TraceRow {
                s0: 0x5700_7998,
                s2: 0x4035_C668,
                s5: 0xB171_4013,
                s11: 0x0AF8_C6D1,
                s15: 0x6673_56A3,
                r1: 0xF13E_06A5,
                r2: 0x79A1_E99D,
                r3: 0x9393_9393,
            },
            TraceRow {
                s0: 0x4E8E_BFEC,
                s2: 0x0AF8_C6D1,
                s5: 0xBFCA_3997,
                s11: 0xA8FF_8667,
                s15: 0x6410_181D,
                r1: 0x9C84_BD1D,
                r2: 0x8EEE_B4AE,
                r3: 0xE599_5CC4,
            },
            TraceRow {
                s0: 0x4035_C668,
                s2: 0xA8FF_8667,
                s5: 0x7397_CE35,
                s11: 0xD3D4_008B,
                s15: 0x241A_7790,
                r1: 0xE942_1A01,
                r2: 0x7519_6F5C,
                r3: 0xC83E_1776,
            },
            TraceRow {
                s0: 0x0AF8_C6D1,
                s2: 0xB171_4013,
                s5: 0x1292_C97F,
                s11: 0xEE2C_ABF5,
                s15: 0xC485_B826,
                r1: 0x30C3_489F,
                r2: 0x36A4_4937,
                r3: 0x0F31_7420,
            },
            TraceRow {
                s0: 0xA8FF_8667,
                s2: 0xBFCA_3997,
                s5: 0x4E8E_BFEC,
                s11: 0x6673_56A3,
                s15: 0xA211_C1E9,
                r1: 0x5448_0696,
                r2: 0x02D9_0971,
                r3: 0x3D98_2023,
            },
            TraceRow {
                s0: 0xB171_4013,
                s2: 0x7397_CE35,
                s5: 0x5B93_3FDF,
                s11: 0x6410_181D,
                s15: 0x6E8A_E7E6,
                r1: 0x75EF_A940,
                r2: 0xD63B_98F8,
                r3: 0x883F_13A7,
            },
        ];
        let final_lfsr = [
            0xFEAF_BAD8,
            0x1B11_050A,
            0x2370_8014,
            0xAC84_94DB,
            0xED97_D431,
            0xDBBB_59B3,
            0x6CD3_0005,
            0x7EC3_6405,
            0xB20F_02AC,
            0xEB40_7735,
            0x50E4_1A0E,
            0xFFA8_ABC1,
            0xEB48_00A7,
            0xD4E6_749D,
            0xD1C4_52FE,
            0xA92A_3153,
        ];
        let final_fsm = [0x6599_AA50, 0x5EA9_188B, 0xF418_89FC];
        let keystream_rows = [
            TraceRow {
                s0: 0x1B11_050A,
                s2: 0xAC84_94DB,
                s5: 0x6CD3_0005,
                s11: 0xEB48_00A7,
                s15: 0x0FE9_1C6F,
                r1: 0x8E4C_E8DA,
                r2: 0x2DEF_74EA,
                r3: 0x42B4_B0A3,
            },
            TraceRow {
                s0: 0x2370_8014,
                s2: 0xED97_D431,
                s5: 0x7EC3_6405,
                s11: 0xD4E6_749D,
                s15: 0xC3CB_3734,
                r1: 0x5C57_2590,
                r2: 0x79B5_1828,
                r3: 0x2496_A1E1,
            },
            TraceRow {
                s0: 0xAC84_94DB,
                s2: 0xDBBB_59B3,
                s5: 0xB20F_02AC,
                s11: 0xD1C4_52FE,
                s15: 0x739A_B29C,
                r1: 0xD40A_DE0C,
                r2: 0x5037_B990,
                r3: 0x32D1_FAE0,
            },
        ];
        let outputs = [0xA8C8_74A9, 0x7AE7_C4F8];

        let case = OfficialTraceCase {
            key,
            iv,
            initial_lfsr,
            init_rows,
            final_lfsr,
            final_fsm,
            keystream_rows,
            outputs,
        };
        assert_official_trace::<false>(&case);
        assert_official_trace::<true>(&case);
    }

    /// Document 3 §3.6, Test Set 4, "Iterated test for full tables coverage":
    /// z1, z2, z3, and z2500, through both paths.
    #[test]
    fn official_test_set_4_iterated_fast_and_ct() {
        assert_iterated_test_set_4::<false>();
        assert_iterated_test_set_4::<true>();
    }
}
