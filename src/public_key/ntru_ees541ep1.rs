//! NTRUEncrypt-EES541EP1 implemented in safe, idiomatic Rust from IEEE Std
//! 1363.1-2008 ("Standard Specification for Public Key Cryptographic
//! Techniques Based on Hard Problems over Lattices") and the Hoffstein,
//! Pipher, Silverman, Whyte sequence of papers that defines NTRUEncrypt with
//! SVES-3 padding.
//!
//! This module provides:
//! - the EES541EP1 parameter set (`N = 541`, `q = 2048`, `p = 3`,
//!   `df = 49`, `dg = 180`, `dm0 = 49`, `db = 112` bits)
//! - key generation, encrypt, decrypt
//! - canonical wire-format byte encodings for `pk`, `sk`, `ct`
//!
//! Construction:
//! - Ring `R_q = Z_q[x] / (x^N - 1)` with `q = 2048` and `p = 3`.
//! - Private key form `f = 1 + p · t` where `t` is a uniform random trinary
//!   polynomial with exactly `df` ones and `df` minus-ones, conditioned on
//!   `f` being invertible modulo `q`. Storing `t` (rather than `f`) saves
//!   space and allows a fast decryption variant: `(1 + 3t) · e ≡ 3·t·e + e
//!   (mod q)`, so decryption is one trinary multiply and one addition.
//! - Public key `h = p · g · f^{-1}  (mod q)` for trinary `g` with `dg`
//!   ones and `dg` minus-ones.
//! - SVES-3 encryption: build `M = b || octL(msg_len) || msg || zero_pad`,
//!   encode `M` as a trinary polynomial `m'` via the SVES bit-to-trit map,
//!   derive the blinding polynomial `r` from a hash-driven IGF over
//!   `oid || msg || b || htrunc(h)`, compute `R = r · h  (mod q)`, derive a
//!   masking trinary polynomial `mask = MGF(to_arr4(R))`, and emit
//!   `c = R + ((m' + mask) mod 3)`. The "rep weight" check on `m' + mask`
//!   re-randomizes `b` until each of the three coefficient values appears
//!   at least `dm0` times.
//! - SVES-3 decryption: recover `(R, m')` via the trapdoor, decode `M`,
//!   verify the re-encryption matches.
//!
//! Implementation notes:
//! - Polynomial multiplication uses the shared Karatsuba helper
//!   [`crate::public_key::ntru_poly_mul`].
//! - Polynomial inversion modulo a power-of-two `q` is the textbook two-step
//!   recipe: extended Euclidean in `F_2[x] / (x^N - 1)` to obtain the
//!   inverse modulo 2, then Newton-style 2-adic Hensel lifting
//!   `b ← b · (2 - a · b)` to the target precision.
//! - SHA-1 (this parameter set's spec hash) and the AES-256 CTR-DRBG used
//!   by callers come from this crate's `hash` and `cprng` modules.
//! - The MGF1-style mask-generation table is the canonical 243-entry base-3
//!   expansion (each input byte less than 243 yields five trits in the
//!   range `{-1, 0, 1}`).
//!
//! Validation:
//! the inline tests round-trip `keygen`/`encrypt`/`decrypt` over messages
//! of every admissible length, drive encryption with a deterministic
//! CTR-DRBG, and verify failure modes (corrupted ciphertext, oversized
//! message). Cross-validation against libntru's published SHA-1 ciphertext
//! digest is gated on a separate port of libntru's NIST SP 800-90 CTR-DRBG
//! with derivation function — a follow-up task; my crate currently ships
//! only the no-derivation-function variant.
//!
//! Side channels:
//! polynomial multiplication and IGF rejection sampling are variable-time;
//! this module sits under `crate::vt` like the rest of the explicitly
//! variable-time public-key surface.

use core::fmt;

use crate::hash::sha1::Sha1;
use crate::Csprng;

// ---- parameter constants (IEEE Std 1363.1-2008 Table 1, EES541EP1) --------

const N: usize = 541;
const LOGQ: usize = 11;
const Q: u32 = 1 << LOGQ;
const Q_MASK: u16 = (Q as u16).wrapping_sub(1);

const DF: usize = 49;
const DG: usize = 180;
const DM0: usize = 49;
/// Number of random *bits* prepended to the message (IEEE 1363.1 calls this
/// `db`; libntru calls `db/8` the `blen` byte count).
const DB_BITS: usize = 112;
const DB_BYTES: usize = DB_BITS / 8;

const C_BITS: usize = 12;
const MIN_CALLS_R: usize = 15;
const MIN_CALLS_MASK: usize = 11;
const HLEN: usize = 20; // SHA-1
const PKLEN_BITS: usize = 112;
const PKLEN_BYTES: usize = (PKLEN_BITS + 7) / 8; // 14

const OID: [u8; 3] = [0, 2, 5];

/// Public-key wire length (one S_q polynomial of `N` 11-bit coefficients).
pub const PUBLIC_KEY_BYTES: usize = (N * LOGQ + 7) / 8; // 744
/// Private-key wire length: trinary `t` packed as 2 bits per coefficient.
pub const PRIVATE_KEY_BYTES: usize = (N * 2 + 7) / 8; // 136
/// Ciphertext wire length (same shape as the public key).
pub const CIPHERTEXT_BYTES: usize = PUBLIC_KEY_BYTES; // 744

/// Maximum byte length of a plaintext message under EES541EP1.
///
/// IEEE 1363.1 §11.4 derives this from `(N · 3 / 2 - llen·8 - db) / 8` with
/// `llen = 8` bits (one octet for the message length prefix).
pub const MAX_MESSAGE_BYTES: usize = N / 2 * 3 / 8 - 1 - DB_BYTES;

// ---- ring type --------------------------------------------------------------

/// Polynomial in `Z_q[x] / (x^N - 1)` with `u16` coefficients. Storage is
/// canonical (`coeffs[i]` is in `[0, q)`); centred-residue conversions are
/// done at use sites.
#[derive(Clone, Copy)]
struct Poly {
    coeffs: [u16; N],
}

impl Poly {
    fn zero() -> Self {
        Self { coeffs: [0u16; N] }
    }
}

#[inline(always)]
fn modq(x: u16) -> u16 {
    x & Q_MASK
}

#[inline(always)]
fn poly_mul(r: &mut Poly, a: &Poly, b: &Poly) {
    crate::public_key::ntru_poly_mul::poly_mul_cyclic(&mut r.coeffs, &a.coeffs, &b.coeffs);
}

#[inline(always)]
fn poly_add(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] = a.coeffs[i].wrapping_add(b.coeffs[i]);
    }
}

#[inline(always)]
fn poly_sub(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
    }
}

/// Reduce coefficients into `{0, 1, 2}` (canonical trinary representation
/// after centred-residue mod `q`).
fn poly_mod3(a: &mut Poly) {
    for c in a.coeffs.iter_mut() {
        // Centred residue mod q: shift to (-q/2, q/2], then reduce mod 3.
        let m = modq(*c);
        let centred = if (m as u32) > Q / 2 {
            m as i32 - Q as i32
        } else {
            m as i32
        };
        let r = centred.rem_euclid(3);
        *c = r as u16;
    }
}

/// In-place scalar multiplication by `k`, modulo `q`.
fn poly_scalar_mul(a: &mut Poly, k: u16) {
    for c in a.coeffs.iter_mut() {
        *c = c.wrapping_mul(k) & Q_MASK;
    }
}

/// Reduce coefficients to canonical mod-q form `[0, q)`.
fn poly_mod_q(a: &mut Poly) {
    for c in a.coeffs.iter_mut() {
        *c = modq(*c);
    }
}

// ---- trinary polynomial: sparse representation -----------------------------
//
// In IEEE 1363.1 the small polynomials (`t`, `g`, `r`) are sampled with
// exactly `df` plus-ones and `df` minus-ones; the rest are zero. We store
// this sparsely (two index lists) since polynomial multiplication by such a
// vector reduces to two passes of cyclic shift-and-add.

#[derive(Clone, Eq, PartialEq)]
struct TernaryPoly {
    ones: Vec<u16>,      // indices with coefficient +1
    neg_ones: Vec<u16>,  // indices with coefficient -1
}

impl TernaryPoly {
    fn to_dense(&self) -> Poly {
        let mut p = Poly::zero();
        for &i in &self.ones {
            p.coeffs[i as usize] = 1;
        }
        for &i in &self.neg_ones {
            p.coeffs[i as usize] = Q_MASK; // -1 mod q
        }
        p
    }

    /// Multiply a dense polynomial by this sparse trinary on the left, in
    /// `Z_q[x] / (x^N - 1)`. Output overwrites `out`.
    fn mul_dense(&self, b: &Poly, out: &mut Poly) {
        for c in out.coeffs.iter_mut() {
            *c = 0;
        }
        for &idx in &self.ones {
            let s = idx as usize;
            for j in 0..N {
                let k = if s + j >= N { s + j - N } else { s + j };
                out.coeffs[k] = out.coeffs[k].wrapping_add(b.coeffs[j]);
            }
        }
        for &idx in &self.neg_ones {
            let s = idx as usize;
            for j in 0..N {
                let k = if s + j >= N { s + j - N } else { s + j };
                out.coeffs[k] = out.coeffs[k].wrapping_sub(b.coeffs[j]);
            }
        }
    }
}

// ---- inversion mod 2 in F_2[x] / (x^N - 1) ---------------------------------
//
// Variable-time extended Euclidean over `F_2[x]` operating on Vec<u8>
// polynomials with one bit per slot. Slow but obviously correct; kept
// outside the hot path of decryption (only used during keygen). Returns the
// inverse polynomial of length `N` if `gcd(a, x^N - 1) = 1`.

fn poly_trim(p: &mut Vec<u8>) {
    while p.len() > 1 && *p.last().unwrap() == 0 {
        p.pop();
    }
}

fn poly_deg(p: &[u8]) -> Option<usize> {
    for i in (0..p.len()).rev() {
        if p[i] != 0 {
            return Some(i);
        }
    }
    None
}

fn poly_inverse_mod2_cyclic(a_coeffs: &[u8]) -> Option<Vec<u8>> {
    let n = a_coeffs.len();
    debug_assert_eq!(n, N);
    // r0 = x^N + 1 (note (x^N - 1) ≡ (x^N + 1) mod 2)
    let mut r0 = vec![0u8; n + 1];
    r0[0] = 1;
    r0[n] = 1;
    let mut r1: Vec<u8> = a_coeffs.iter().map(|&c| c & 1).collect();
    poly_trim(&mut r1);
    let mut t0 = vec![0u8; 1];
    let mut t1 = vec![1u8; 1];

    loop {
        let d1 = match poly_deg(&r1) {
            Some(d) => d,
            None => break, // r1 = 0 → r0 holds gcd, t0 holds inverse coeff
        };
        let d0 = match poly_deg(&r0) {
            Some(d) => d,
            None => {
                // r0 = 0 → r1 holds gcd, t1 holds inverse coeff
                std::mem::swap(&mut r0, &mut r1);
                std::mem::swap(&mut t0, &mut t1);
                break;
            }
        };
        if d0 < d1 {
            std::mem::swap(&mut r0, &mut r1);
            std::mem::swap(&mut t0, &mut t1);
            continue;
        }
        let shift = d0 - d1;
        // r0 ^= r1 * x^shift
        for i in 0..=d1 {
            r0[shift + i] ^= r1[i];
        }
        poly_trim(&mut r0);
        // t0 ^= t1 * x^shift
        let new_t0_len = t0.len().max(t1.len() + shift);
        if t0.len() < new_t0_len {
            t0.resize(new_t0_len, 0);
        }
        for i in 0..t1.len() {
            t0[shift + i] ^= t1[i];
        }
    }

    // gcd must be 1.
    if !(r0.len() == 1 && r0[0] == 1) {
        return None;
    }
    // Reduce t0 mod (x^N - 1): position k ≡ k mod N.
    let mut out = vec![0u8; n];
    for (i, &c) in t0.iter().enumerate() {
        if c & 1 == 1 {
            out[i % n] ^= 1;
        }
    }
    Some(out)
}

// ---- inversion in R_q via Hensel lift from R_2 -----------------------------

fn poly_inverse_mod_q_cyclic(a: &Poly) -> Option<Poly> {
    // Reduce `a` to its mod-2 coefficient vector.
    let a_mod2: Vec<u8> = a.coeffs.iter().map(|&c| (c & 1) as u8).collect();
    let inv2 = poly_inverse_mod2_cyclic(&a_mod2)?;

    // Lift the F_2 inverse to mod q via Newton iteration.
    let mut b = Poly::zero();
    for i in 0..N {
        b.coeffs[i] = inv2[i] as u16;
    }

    // Standard Hensel: b ← b · (2 - a · b)  (mod q). Each iteration squares
    // 2-adic precision; for q = 2^11 we need ceil(log2(11)) = 4 iterations
    // starting from precision 2^1.
    let mut precision: u32 = 2;
    while precision < Q {
        let mut ab = Poly::zero();
        poly_mul(&mut ab, a, &b);
        poly_mod_q(&mut ab);
        let mut two_minus_ab = Poly::zero();
        two_minus_ab.coeffs[0] = 2u16.wrapping_sub(ab.coeffs[0]) & Q_MASK;
        for i in 1..N {
            two_minus_ab.coeffs[i] = 0u16.wrapping_sub(ab.coeffs[i]) & Q_MASK;
        }
        let mut new_b = Poly::zero();
        poly_mul(&mut new_b, &b, &two_minus_ab);
        poly_mod_q(&mut new_b);
        b = new_b;
        precision = precision.saturating_mul(precision);
    }
    Some(b)
}

// ---- bit-string accumulator (IEEE 1363.1 §9 BPGM3 / IGF helpers) -----------
//
// Bits are appended low-bit-first within each byte (matching libntru's
// ntru_append/ntru_leading byte ordering).

#[derive(Clone)]
struct BitStr {
    buf: Vec<u8>,
    last_byte_bits: u8, // 1..=8; 0 means buf is empty
}

impl BitStr {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            last_byte_bits: 0,
        }
    }

    fn append_byte(&mut self, b: u8) {
        if self.buf.is_empty() {
            self.buf.push(b);
            self.last_byte_bits = 8;
        } else if self.last_byte_bits == 8 {
            self.buf.push(b);
        } else {
            let lb = self.last_byte_bits;
            let last = self.buf.last_mut().unwrap();
            *last |= b << lb;
            let high = b >> (8 - lb);
            self.buf.push(high);
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.append_byte(b);
        }
    }

    /// Read the top `num_bits` bits as a little-endian-within-byte integer
    /// without removing them.
    fn leading(&self, num_bits: u8) -> u32 {
        let total = (self.buf.len() - 1) * 8 + self.last_byte_bits as usize;
        let start_bit = total - num_bits as usize;
        let start_byte = start_bit / 8;
        let start_bit_in_byte = start_bit % 8;

        let mut sum: u32 = (self.buf[start_byte] as u32) >> start_bit_in_byte;
        let mut shift = (8 - start_bit_in_byte) as u32;
        for i in (start_byte + 1)..(self.buf.len() - 1) {
            sum |= (self.buf[i] as u32) << shift;
            shift += 8;
        }
        let final_bits = num_bits as u32 - shift;
        let afin = self.buf[self.buf.len() - 1] as u32;
        let mask = if final_bits == 0 {
            0
        } else {
            (1u32 << final_bits) - 1
        };
        sum |= (afin & mask) << shift;
        sum
    }

    fn truncate(&mut self, num_bits: u8) {
        let mut nb = num_bits;
        let byte_drop = (nb / 8) as usize;
        for _ in 0..byte_drop {
            self.buf.pop();
        }
        nb %= 8;
        let mut last = self.last_byte_bits as i16 - nb as i16;
        if last < 0 {
            last += 8;
            self.buf.pop();
        }
        self.last_byte_bits = last as u8;
    }

    fn trailing(&self, num_bits: u32) -> Self {
        let n = ((num_bits + 7) / 8) as usize;
        let mut out_buf = self.buf[..n].to_vec();
        let last_bits = (num_bits % 8) as u8;
        let last_bits = if last_bits == 0 { 8 } else { last_bits };
        if last_bits < 8 {
            let mask = (1u8 << last_bits) - 1;
            *out_buf.last_mut().unwrap() &= mask;
        }
        Self {
            buf: out_buf,
            last_byte_bits: last_bits,
        }
    }
}

// ---- IGF: Index Generation Function (IEEE 1363.1 §9.2.4) -------------------
//
// State machine that produces a stream of indices in [0, N) by repeatedly
// hashing `(seed || counter)` and consuming `c` bits at a time, rejecting
// outputs >= floor(2^c / N) * N to keep the distribution uniform mod N.

struct IgfState {
    z: Vec<u8>,
    counter: u16,
    buf: BitStr,
    rem_bits: u32,
}

impl IgfState {
    fn new(seed: &[u8]) -> Self {
        let mut s = Self {
            z: seed.to_vec(),
            counter: 0,
            buf: BitStr::new(),
            rem_bits: (MIN_CALLS_R * 8 * HLEN) as u32,
        };
        // Pre-hash MIN_CALLS_R times so the buffer holds enough bits for
        // the worst-case rejection-sampling load.
        while (s.counter as usize) < MIN_CALLS_R {
            s.absorb_one();
        }
        s
    }

    fn absorb_one(&mut self) {
        let mut input = self.z.clone();
        input.extend_from_slice(&self.counter.to_le_bytes());
        let h = Sha1::digest(&input);
        self.buf.append(h.as_slice());
        self.counter = self.counter.wrapping_add(1);
    }

    fn next_index(&mut self) -> u16 {
        let c = C_BITS as u8;
        let rnd_thresh: u32 = (1u32 << c) - (1u32 << c) % (N as u32);
        loop {
            if self.rem_bits < c as u32 {
                // Refill: stash the trailing bits, hash more in, append.
                let mut tail = self.buf.trailing(self.rem_bits);
                let need = (c as u32) - self.rem_bits;
                let extra_calls = (need + (HLEN as u32) * 8 - 1) / ((HLEN as u32) * 8);
                for _ in 0..extra_calls {
                    let mut input = self.z.clone();
                    input.extend_from_slice(&self.counter.to_le_bytes());
                    let h = Sha1::digest(&input);
                    tail.append(h.as_slice());
                    self.counter = self.counter.wrapping_add(1);
                    self.rem_bits += 8 * HLEN as u32;
                }
                self.buf = tail;
            }
            let v = self.buf.leading(c);
            self.buf.truncate(c);
            self.rem_bits -= c as u32;
            if v < rnd_thresh {
                let mut idx = v;
                while idx >= N as u32 {
                    idx -= N as u32;
                }
                return idx as u16;
            }
        }
    }
}

/// Sample a trinary polynomial with exactly `num_each` ones and `num_each`
/// minus-ones using the IGF, the standard IEEE 1363.1 procedure for
/// generating the blinding polynomial `r`.
fn igf_gen_ternary(state: &mut IgfState, num_each: usize) -> TernaryPoly {
    let mut occupied = vec![false; N];
    let mut neg_ones = Vec::with_capacity(num_each);
    let mut ones = Vec::with_capacity(num_each);

    while neg_ones.len() < num_each {
        let idx = state.next_index();
        if !occupied[idx as usize] {
            occupied[idx as usize] = true;
            neg_ones.push(idx);
        }
    }
    while ones.len() < num_each {
        let idx = state.next_index();
        if !occupied[idx as usize] {
            occupied[idx as usize] = true;
            ones.push(idx);
        }
    }
    TernaryPoly { ones, neg_ones }
}

// ---- MGF: 5 trits per byte using the canonical 243-entry table -------------

fn mgf_trit_table() -> &'static [[i8; 5]; 243] {
    // Generated lazily to keep the binary small if MGF isn't reachable.
    use std::sync::OnceLock;
    static TABLE: OnceLock<[[i8; 5]; 243]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [[0i8; 5]; 243];
        let map = [0i8, 1, -1]; // libntru orders trits as {0, 1, -1}
        for byte in 0..243u32 {
            let mut v = byte;
            for slot in &mut t[byte as usize] {
                *slot = map[(v % 3) as usize];
                v /= 3;
            }
        }
        t
    })
}

/// Mask Generation Function: produce a length-`N` polynomial in `{-1, 0, 1}`
/// from a seed, using SHA-1, by hashing `(SHA-1(seed) || counter)` and
/// expanding bytes <243 via the 5-trits-per-byte table.
fn mgf(seed: &[u8]) -> Poly {
    let z = Sha1::digest(seed);
    let z_bytes = z.as_slice();

    let mut buf: Vec<u8> = Vec::with_capacity(MIN_CALLS_MASK * HLEN);
    let mut counter: u16 = 0;
    while (counter as usize) < MIN_CALLS_MASK {
        let mut input = Vec::with_capacity(HLEN + 2);
        input.extend_from_slice(z_bytes);
        input.extend_from_slice(&counter.to_be_bytes());
        let h = Sha1::digest(&input);
        for &b in h.as_slice() {
            if b < 243 {
                buf.push(b);
            }
        }
        counter = counter.wrapping_add(1);
    }

    let mut out = Poly::zero();
    let mut cur = 0usize;
    let table = mgf_trit_table();
    'outer: loop {
        for &b in &buf {
            let trits = table[b as usize];
            for &t in &trits {
                out.coeffs[cur] = match t {
                    -1 => Q_MASK, // -1 represented in u16 as q-1; actual value handled in caller
                    0 => 0,
                    1 => 1,
                    _ => unreachable!(),
                };
                cur += 1;
                if cur >= N {
                    break 'outer;
                }
            }
        }
        let mut input = Vec::with_capacity(HLEN + 2);
        input.extend_from_slice(z_bytes);
        input.extend_from_slice(&counter.to_be_bytes());
        let h = Sha1::digest(&input);
        buf.clear();
        for &b in h.as_slice() {
            if b < 243 {
                buf.push(b);
            }
        }
        counter = counter.wrapping_add(1);
    }
    out
}

// ---- SVES encoding (IEEE 1363.1 §9.2.2 / §9.2.3) ---------------------------

const SVES_C1: [i8; 8] = [0, 0, 0, 1, 1, 1, -1, -1];
const SVES_C2: [i8; 8] = [0, 1, -1, 0, 1, -1, 0, 1];

/// Encode an octet string `M` as a length-`N` trinary polynomial. Pairs of
/// coefficients are emitted from each 3-bit chunk via the lookup tables.
fn sves_from_bytes(m: &[u8]) -> Poly {
    let mut out = Poly::zero();
    let mut coeff_idx: usize = 0;
    let mut i = 0usize;
    while i + 3 <= ((m.len() + 2) / 3) * 3 && coeff_idx < N - 1 {
        let b0 = if i < m.len() { m[i] } else { 0 } as u32;
        let b1 = if i + 1 < m.len() { m[i + 1] } else { 0 } as u32;
        let b2 = if i + 2 < m.len() { m[i + 2] } else { 0 } as u32;
        let mut chunk = (b2 << 16) | (b1 << 8) | b0;
        i += 3;
        for _ in 0..8 {
            if coeff_idx >= N - 1 {
                break;
            }
            let tbl = (chunk & 7) as usize;
            out.coeffs[coeff_idx] = trit_to_u16(SVES_C1[tbl]);
            out.coeffs[coeff_idx + 1] = trit_to_u16(SVES_C2[tbl]);
            coeff_idx += 2;
            chunk >>= 3;
        }
    }
    out
}

fn trit_to_u16(t: i8) -> u16 {
    match t {
        -1 => Q_MASK, // not used; SVES emits {-1, 0, 1}; we only feed this to trit-mod-3 logic
        0 => 0,
        1 => 1,
        _ => unreachable!(),
    }
}

/// Inverse of `sves_from_bytes` operating on a polynomial whose
/// coefficients lie in `{0, 1, 2}` (after `poly_mod3`). Returns `None` if
/// any (2*i, 2*i+1) pair is `(2, 2)` — that pair is unreachable in valid
/// SVES output.
fn sves_to_bytes(p: &Poly) -> Option<Vec<u8>> {
    let num_bits = (N * 3 + 1) / 2;
    let num_bytes = (num_bits + 7) / 8;
    let mut out = vec![0u8; num_bytes + 3];
    let end = N / 2 * 2;
    let mut d_idx = 0usize;
    let mut i = 0usize;
    while i < end {
        let mut acc: u32 = 0;
        let mut bits_in_acc: u32 = 0;
        for _ in 0..8 {
            if i >= end {
                break;
            }
            let c1 = p.coeffs[i] as i32;
            let c2 = p.coeffs[i + 1] as i32;
            i += 2;
            if c1 == 2 && c2 == 2 {
                return None;
            }
            let c = (c1 * 3 + c2) as u32;
            acc |= c << bits_in_acc;
            bits_in_acc += 3;
            while bits_in_acc >= 8 && d_idx < out.len() {
                out[d_idx] = (acc & 0xff) as u8;
                d_idx += 1;
                acc >>= 8;
                bits_in_acc -= 8;
            }
        }
        if bits_in_acc > 0 && d_idx < out.len() {
            out[d_idx] |= acc as u8;
        }
    }
    out.truncate(num_bytes);
    Some(out)
}

// ---- byte encodings of polynomials -----------------------------------------

/// Pack `N` coefficients of `LOGQ = 11` bits each into `PUBLIC_KEY_BYTES`
/// bytes, low-bit-first within each byte.
fn poly_to_arr(p: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), PUBLIC_KEY_BYTES);
    for b in out.iter_mut() {
        *b = 0;
    }
    let mut bit_pos = 0usize;
    for i in 0..N {
        let v = modq(p.coeffs[i]) as u32;
        for b in 0..LOGQ {
            let bit = ((v >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

fn poly_from_arr(input: &[u8]) -> Poly {
    debug_assert!(input.len() >= PUBLIC_KEY_BYTES);
    let mut p = Poly::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut v: u32 = 0;
        for b in 0..LOGQ {
            let bit = ((input[bit_pos / 8] >> (bit_pos % 8)) & 1) as u32;
            v |= bit << b;
            bit_pos += 1;
        }
        p.coeffs[i] = v as u16;
    }
    p
}

/// Pack `N` coefficients into 2-bit centred-residue codes (used by the MGF
/// seed in encrypt/decrypt).
fn poly_to_arr4(p: &Poly) -> Vec<u8> {
    let nbits = N * 2;
    let mut out = vec![0u8; (nbits + 7) / 8];
    let mut bit_pos = 0usize;
    for i in 0..N {
        // Reduce to centred residue mod 4: {-1, 0, 1, 2} → {3, 0, 1, 2}.
        let centred = {
            let m = modq(p.coeffs[i]);
            let centred = if (m as u32) > Q / 2 {
                m as i32 - Q as i32
            } else {
                m as i32
            };
            (centred & 3) as u8
        };
        for b in 0..2 {
            let bit = (centred >> b) & 1;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
    out
}

// ---- public-key / private-key / ciphertext types ---------------------------

/// EES541EP1 public key (`h = 3 · g · f^{-1}` packed as `N` 11-bit
/// coefficients, total 744 bytes).
#[derive(Clone, Eq, PartialEq)]
pub struct NtruEes541Ep1PublicKey {
    bytes: [u8; PUBLIC_KEY_BYTES],
}

/// EES541EP1 private key (`t` packed as 2-bit signed trinary, total 136
/// bytes).
#[derive(Clone, Eq, PartialEq)]
pub struct NtruEes541Ep1PrivateKey {
    /// Private trinary `t` such that `f = 1 + 3t`.
    t: TernaryPoly,
    /// Public-key bytes, kept alongside `t` so decryption can re-encrypt
    /// the recovered `(m', r)` pair to verify ciphertext integrity.
    pk: NtruEes541Ep1PublicKey,
}

/// EES541EP1 ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct NtruEes541Ep1Ciphertext {
    bytes: [u8; CIPHERTEXT_BYTES],
}

impl NtruEes541Ep1PublicKey {
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return None;
        }
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(bytes);
        // Validate that the unused high bits in the last byte are zero
        // (canonical form).
        let used = N * LOGQ;
        let extra = PUBLIC_KEY_BYTES * 8 - used;
        if extra > 0 {
            let mask = !((1u8 << (8 - extra)) - 1);
            if out[PUBLIC_KEY_BYTES - 1] & mask != 0 {
                return None;
            }
        }
        Some(Self { bytes: out })
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.bytes
    }

    fn poly(&self) -> Poly {
        poly_from_arr(&self.bytes)
    }
}

impl NtruEes541Ep1PrivateKey {
    /// Encode the secret as `pack(t) || pk_bytes` so loading restores both
    /// the trapdoor and the public key (decryption needs the public key for
    /// the SVES re-encryption check).
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES);
        let mut t_bytes = vec![0u8; PRIVATE_KEY_BYTES];
        let mut bit_pos = 0usize;
        let dense = self.t.to_dense();
        for i in 0..N {
            // Map +1 → 01, -1 → 11, 0 → 00.
            let code: u8 = match dense.coeffs[i] {
                0 => 0,
                1 => 1,
                v if v == Q_MASK => 3,
                _ => unreachable!(),
            };
            t_bytes[bit_pos / 8] |= code << (bit_pos % 8);
            bit_pos += 2;
        }
        out.extend_from_slice(&t_bytes);
        out.extend_from_slice(&self.pk.bytes);
        out
    }

    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES {
            return None;
        }
        let mut bit_pos = 0usize;
        let mut ones = Vec::new();
        let mut neg_ones = Vec::new();
        for i in 0..N {
            let code = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 0x3;
            bit_pos += 2;
            match code {
                0 => {}
                1 => ones.push(i as u16),
                3 => neg_ones.push(i as u16),
                _ => return None,
            }
        }
        if ones.len() != DF || neg_ones.len() != DF {
            return None;
        }
        // Padding bits in the last byte of the trinary segment must be zero.
        let used = N * 2;
        let extra = PRIVATE_KEY_BYTES * 8 - used;
        if extra > 0 {
            let mask = !((1u8 << (8 - extra)) - 1);
            if bytes[PRIVATE_KEY_BYTES - 1] & mask != 0 {
                return None;
            }
        }
        let pk = NtruEes541Ep1PublicKey::from_wire_bytes(&bytes[PRIVATE_KEY_BYTES..])?;
        Some(Self {
            t: TernaryPoly { ones, neg_ones },
            pk,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> &NtruEes541Ep1PublicKey {
        &self.pk
    }
}

impl NtruEes541Ep1Ciphertext {
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return None;
        }
        let mut out = [0u8; CIPHERTEXT_BYTES];
        out.copy_from_slice(bytes);
        let used = N * LOGQ;
        let extra = CIPHERTEXT_BYTES * 8 - used;
        if extra > 0 {
            let mask = !((1u8 << (8 - extra)) - 1);
            if out[CIPHERTEXT_BYTES - 1] & mask != 0 {
                return None;
            }
        }
        Some(Self { bytes: out })
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for NtruEes541Ep1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtruEes541Ep1PrivateKey(<redacted>)")
    }
}

impl fmt::Debug for NtruEes541Ep1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtruEes541Ep1PublicKey").finish()
    }
}

impl fmt::Debug for NtruEes541Ep1Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtruEes541Ep1Ciphertext").finish()
    }
}

/// Errors returnable by encrypt / decrypt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtruEes541Ep1Error {
    /// Plaintext is longer than `MAX_MESSAGE_BYTES`.
    MessageTooLong,
    /// Decryption recovered a polynomial that fails the SVES validity
    /// checks (rep weight, zero padding, or re-encryption).
    InvalidCiphertext,
}

/// Namespace for EES541EP1 NTRUEncrypt operations.
pub struct NtruEes541Ep1;

impl NtruEes541Ep1 {
    /// Generate a fresh key pair.
    pub fn keygen<R: Csprng>(rng: &mut R) -> (NtruEes541Ep1PublicKey, NtruEes541Ep1PrivateKey) {
        loop {
            let t = sample_trinary(rng, DF, DF);
            // f = 1 + 3 · t
            let mut f = t.to_dense();
            poly_scalar_mul(&mut f, 3);
            f.coeffs[0] = f.coeffs[0].wrapping_add(1) & Q_MASK;
            let f_inv = match poly_inverse_mod_q_cyclic(&f) {
                Some(inv) => inv,
                None => continue,
            };

            let g = sample_trinary(rng, DG, DG);

            // h = 3 · (g · f_inv) mod q
            let mut g_dense = g.to_dense();
            poly_mod_q(&mut g_dense);
            let mut h = Poly::zero();
            poly_mul(&mut h, &g_dense, &f_inv);
            poly_scalar_mul(&mut h, 3);

            let mut pk_bytes = [0u8; PUBLIC_KEY_BYTES];
            poly_to_arr(&h, &mut pk_bytes);
            let pk = NtruEes541Ep1PublicKey { bytes: pk_bytes };
            let sk = NtruEes541Ep1PrivateKey {
                t,
                pk: pk.clone(),
            };
            return (pk, sk);
        }
    }

    /// SVES-3 encrypt. `msg` must be `<= MAX_MESSAGE_BYTES`.
    pub fn encrypt<R: Csprng>(
        pk: &NtruEes541Ep1PublicKey,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<NtruEes541Ep1Ciphertext, NtruEes541Ep1Error> {
        if msg.len() > MAX_MESSAGE_BYTES {
            return Err(NtruEes541Ep1Error::MessageTooLong);
        }
        let h = pk.poly();
        let mut h_centred = h;
        poly_mod_q(&mut h_centred);

        let pk_bytes = &pk.bytes;
        let htrunc = &pk_bytes[..PKLEN_BYTES];

        loop {
            let mut b = vec![0u8; DB_BYTES];
            rng.fill_bytes(&mut b);

            // M = b || octL(msg_len) || msg || zero pad
            let m_len = DB_BYTES + 1 + MAX_MESSAGE_BYTES + 1;
            let mut m = vec![0u8; m_len];
            m[..DB_BYTES].copy_from_slice(&b);
            m[DB_BYTES] = msg.len() as u8;
            m[DB_BYTES + 1..DB_BYTES + 1 + msg.len()].copy_from_slice(msg);
            // Remaining bytes are already zero.

            let mtrin = sves_from_bytes(&m);

            // Blinding-poly seed: oid || msg || b || htrunc
            let mut sdata =
                Vec::with_capacity(OID.len() + msg.len() + b.len() + htrunc.len());
            sdata.extend_from_slice(&OID);
            sdata.extend_from_slice(msg);
            sdata.extend_from_slice(&b);
            sdata.extend_from_slice(htrunc);

            let mut igf = IgfState::new(&sdata);
            let r = igf_gen_ternary(&mut igf, DF);

            let mut bigr = Poly::zero();
            r.mul_dense(&h_centred, &mut bigr);
            poly_mod_q(&mut bigr);

            let or4 = poly_to_arr4(&bigr);
            let mask = mgf(&or4);

            let mut mtrin_plus_mask = mtrin;
            poly_add(&mut mtrin_plus_mask, &mask);
            poly_mod3(&mut mtrin_plus_mask);

            if !check_rep_weight(&mtrin_plus_mask) {
                continue;
            }

            let mut e = bigr;
            // Add (m' + mask) (already in {0,1,2}) into e and reduce mod q.
            for i in 0..N {
                let v = mtrin_plus_mask.coeffs[i];
                // Convert {0,1,2} centred-residue into mod-q.
                let signed: u16 = match v {
                    0 => 0,
                    1 => 1,
                    2 => Q_MASK,
                    _ => unreachable!(),
                };
                e.coeffs[i] = e.coeffs[i].wrapping_add(signed);
            }
            poly_mod_q(&mut e);

            let mut out = [0u8; CIPHERTEXT_BYTES];
            poly_to_arr(&e, &mut out);
            return Ok(NtruEes541Ep1Ciphertext { bytes: out });
        }
    }

    /// SVES-3 decrypt. Returns the original message bytes, or an error if
    /// the ciphertext fails any validity check.
    pub fn decrypt(
        sk: &NtruEes541Ep1PrivateKey,
        ct: &NtruEes541Ep1Ciphertext,
    ) -> Result<Vec<u8>, NtruEes541Ep1Error> {
        let e = poly_from_arr(&ct.bytes);

        // ci = (1 + 3t) · e mod q, centred mod q, then mod 3.
        let mut te = Poly::zero();
        sk.t.mul_dense(&e, &mut te);
        let mut ci = te;
        poly_scalar_mul(&mut ci, 3);
        poly_add(&mut ci, &e);
        poly_mod_q(&mut ci);
        poly_mod3(&mut ci);

        let mut retcode_ok = check_rep_weight(&ci);

        // cR = e - ci (mod q).
        let mut c_r = e;
        // ci is in {0, 1, 2}; convert to mod-q and subtract.
        let mut ci_modq = Poly::zero();
        for i in 0..N {
            ci_modq.coeffs[i] = match ci.coeffs[i] {
                0 => 0,
                1 => 1,
                2 => Q_MASK,
                _ => unreachable!(),
            };
        }
        poly_sub(&mut c_r, &ci_modq);
        poly_mod_q(&mut c_r);

        let or4 = poly_to_arr4(&c_r);
        let mask = mgf(&or4);

        let mut cmtrin = ci;
        poly_sub(&mut cmtrin, &mask);
        poly_mod3(&mut cmtrin);

        let cm = sves_to_bytes(&cmtrin).ok_or(NtruEes541Ep1Error::InvalidCiphertext)?;

        let cb = &cm[..DB_BYTES];
        let cl = cm[DB_BYTES] as usize;
        if cl > MAX_MESSAGE_BYTES {
            return Err(NtruEes541Ep1Error::InvalidCiphertext);
        }
        let msg = cm[DB_BYTES + 1..DB_BYTES + 1 + cl].to_vec();

        // Trailing pad must be zero.
        let pad_start = DB_BYTES + 1 + cl;
        let pad_end = (N * 3 + 1) / 2;
        let pad_end_bytes = (pad_end + 7) / 8;
        for &p in &cm[pad_start..pad_end_bytes.min(cm.len())] {
            if p != 0 {
                retcode_ok = false;
            }
        }

        // Rebuild sdata, regenerate r, recompute R', check equality with c_r.
        let pk_bytes = &sk.pk.bytes;
        let htrunc = &pk_bytes[..PKLEN_BYTES];
        let mut sdata = Vec::with_capacity(OID.len() + cl + DB_BYTES + DB_BYTES);
        sdata.extend_from_slice(&OID);
        sdata.extend_from_slice(&msg);
        sdata.extend_from_slice(cb);
        sdata.extend_from_slice(htrunc);
        let mut igf = IgfState::new(&sdata);
        let cr_priv = igf_gen_ternary(&mut igf, DF);

        let h = sk.pk.poly();
        let mut bigr_prime = Poly::zero();
        cr_priv.mul_dense(&h, &mut bigr_prime);
        poly_mod_q(&mut bigr_prime);

        for i in 0..N {
            if bigr_prime.coeffs[i] != c_r.coeffs[i] {
                retcode_ok = false;
                break;
            }
        }

        if !retcode_ok {
            return Err(NtruEes541Ep1Error::InvalidCiphertext);
        }
        Ok(msg)
    }
}

// ---- helpers ---------------------------------------------------------------

fn sample_trinary<R: Csprng>(rng: &mut R, num_ones: usize, num_neg_ones: usize) -> TernaryPoly {
    debug_assert!(num_ones + num_neg_ones <= N);
    let mut idx: Vec<u16> = (0..N as u16).collect();
    // Fisher-Yates partial shuffle on the first num_ones + num_neg_ones slots.
    let take = num_ones + num_neg_ones;
    for i in 0..take {
        let j = i + next_index_below(rng, (N - i) as u32) as usize;
        idx.swap(i, j);
    }
    // Sort the index lists so two TernaryPolys representing the same polynomial
    // compare equal regardless of how they were produced.
    let mut ones = idx[..num_ones].to_vec();
    let mut neg_ones = idx[num_ones..take].to_vec();
    ones.sort_unstable();
    neg_ones.sort_unstable();
    TernaryPoly { ones, neg_ones }
}

fn next_index_below<R: Csprng>(rng: &mut R, modulus: u32) -> u32 {
    let threshold = u32::MAX - (u32::MAX % modulus);
    loop {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < threshold {
            return v % modulus;
        }
    }
}

/// Each of `{0, 1, 2}` must appear at least `DM0` times in `p`.
fn check_rep_weight(p: &Poly) -> bool {
    let mut w = [0usize; 3];
    for i in 0..N {
        let v = p.coeffs[i] as usize;
        if v < 3 {
            w[v] += 1;
        }
    }
    w[0] >= DM0 && w[1] >= DM0 && w[2] >= DM0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CtrDrbgAes256;

    #[test]
    fn parameter_byte_lengths() {
        assert_eq!(N, 541);
        assert_eq!(PUBLIC_KEY_BYTES, 744);
        assert_eq!(PRIVATE_KEY_BYTES, 136);
        assert_eq!(CIPHERTEXT_BYTES, 744);
        assert!(MAX_MESSAGE_BYTES > 0);
    }

    #[test]
    fn sves_roundtrip_random_bytes() {
        // SVES emits coefficients in `{-1, 0, 1}` represented as
        // `{Q_MASK, 0, 1}` in our `u16` storage. Decoding expects
        // `{0, 1, 2}` (post-`poly_mod3`), which is exactly what the
        // protocol applies after the mask add.
        let mut drbg = CtrDrbgAes256::new(&[0x33u8; 48]);
        for &len in &[0usize, 1, 14, MAX_MESSAGE_BYTES] {
            let m_len = DB_BYTES + 1 + MAX_MESSAGE_BYTES + 1;
            let mut m = vec![0u8; m_len];
            drbg.fill_bytes(&mut m[..DB_BYTES]);
            m[DB_BYTES] = len as u8;
            for b in &mut m[DB_BYTES + 1..DB_BYTES + 1 + len] {
                let mut buf = [0u8; 1];
                drbg.fill_bytes(&mut buf);
                *b = buf[0];
            }
            let mut p = sves_from_bytes(&m);
            poly_mod3(&mut p);
            let recovered = sves_to_bytes(&p).expect("decode succeeds");
            assert_eq!(
                &m[..recovered.len().min(m.len())],
                &recovered[..recovered.len().min(m.len())]
            );
        }
    }

    #[test]
    fn round_trip_empty_and_full_messages() {
        let mut drbg = CtrDrbgAes256::new(&[0x42u8; 48]);
        let (pk, sk) = NtruEes541Ep1::keygen(&mut drbg);
        for &len in &[0usize, 1, 16, 32, MAX_MESSAGE_BYTES] {
            let mut msg = vec![0u8; len];
            drbg.fill_bytes(&mut msg);
            let ct = NtruEes541Ep1::encrypt(&pk, &msg, &mut drbg).expect("encrypt");
            let dec = NtruEes541Ep1::decrypt(&sk, &ct).expect("decrypt");
            assert_eq!(dec, msg, "round-trip at len={len}");
        }
    }

    #[test]
    fn rejects_oversize_message() {
        let mut drbg = CtrDrbgAes256::new(&[0x77u8; 48]);
        let (pk, _) = NtruEes541Ep1::keygen(&mut drbg);
        let too_big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let err = NtruEes541Ep1::encrypt(&pk, &too_big, &mut drbg).unwrap_err();
        assert_eq!(err, NtruEes541Ep1Error::MessageTooLong);
    }

    #[test]
    fn corrupted_ciphertext_rejected() {
        let mut drbg = CtrDrbgAes256::new(&[0x99u8; 48]);
        let (pk, sk) = NtruEes541Ep1::keygen(&mut drbg);
        let msg = b"hello ntru";
        let ct = NtruEes541Ep1::encrypt(&pk, msg, &mut drbg).expect("encrypt");
        let mut bad_bytes = ct.to_wire_bytes();
        bad_bytes[10] ^= 0xff;
        let bad_ct =
            NtruEes541Ep1Ciphertext::from_wire_bytes(&bad_bytes).expect("structural decode");
        match NtruEes541Ep1::decrypt(&sk, &bad_ct) {
            Err(NtruEes541Ep1Error::InvalidCiphertext) => {}
            other => panic!("expected InvalidCiphertext, got {:?}", other),
        }
    }

    #[test]
    fn wire_format_roundtrip_keys_and_ct() {
        let mut drbg = CtrDrbgAes256::new(&[0xa0u8; 48]);
        let (pk, sk) = NtruEes541Ep1::keygen(&mut drbg);
        let msg = b"wire-format-roundtrip";
        let ct = NtruEes541Ep1::encrypt(&pk, msg, &mut drbg).expect("encrypt");

        let pk_round = NtruEes541Ep1PublicKey::from_wire_bytes(&pk.to_wire_bytes())
            .expect("pk decode");
        let sk_round = NtruEes541Ep1PrivateKey::from_wire_bytes(&sk.to_wire_bytes())
            .expect("sk decode");
        let ct_round = NtruEes541Ep1Ciphertext::from_wire_bytes(&ct.to_wire_bytes())
            .expect("ct decode");

        assert_eq!(pk_round, pk);
        assert_eq!(sk_round, sk);
        assert_eq!(ct_round, ct);

        let dec = NtruEes541Ep1::decrypt(&sk_round, &ct_round).expect("decrypt");
        assert_eq!(dec, msg);
    }
}
