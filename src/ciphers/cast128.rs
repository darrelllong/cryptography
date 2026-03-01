//! CAST-128 / CAST5 block cipher — RFC 2144.
//!
//! 64-bit block cipher with variable key sizes from 40 to 128 bits in 8-bit
//! increments. The default `Cast128::new` constructor uses the full 128-bit
//! key size and therefore all 16 rounds. `with_key_bytes` supports the RFC's
//! shorter key sizes and automatically drops to 12 rounds for keys up to
//! and including 80 bits.
//!
//! The fast path keeps the direct 8-bit S-box tables from RFC 2144 Appendix A.
//! `Cast128Ct` uses a fixed-scan table selection helper so the round function
//! and key schedule avoid secret-indexed table reads in portable software.

use crate::ct::{ct_lookup_u32, zeroize_slice};
use crate::BlockCipher;

include!("cast128_tables.rs");

#[inline(always)]
fn sbox(table: &[u32; 256], idx: u8, use_ct: bool) -> u32 {
    if use_ct {
        ct_lookup_u32(table, idx)
    } else {
        table[idx as usize]
    }
}

#[inline(always)]
fn pack(bytes: &[u8; 16], a: usize, b: usize, c: usize, d: usize) -> u32 {
    u32::from_be_bytes([bytes[a], bytes[b], bytes[c], bytes[d]])
}

#[inline(always)]
fn unpack(bytes: &mut [u8; 16], start: usize, value: u32) {
    bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

// The RFC key schedule alternates between 16-byte `x` and `z` states; these
// helpers implement those byte-to-byte recurrences directly so the published
// K1..K32 formulas stay readable.
fn x_to_z(x: &[u8; 16], use_ct: bool) -> [u8; 16] {
    let mut z = [0u8; 16];
    let w0 = pack(x, 0, 1, 2, 3)
        ^ sbox(&S5, x[13], use_ct)
        ^ sbox(&S6, x[15], use_ct)
        ^ sbox(&S7, x[12], use_ct)
        ^ sbox(&S8, x[14], use_ct)
        ^ sbox(&S7, x[8], use_ct);
    unpack(&mut z, 0, w0);

    let w1 = pack(x, 8, 9, 10, 11)
        ^ sbox(&S5, z[0], use_ct)
        ^ sbox(&S6, z[2], use_ct)
        ^ sbox(&S7, z[1], use_ct)
        ^ sbox(&S8, z[3], use_ct)
        ^ sbox(&S8, x[10], use_ct);
    unpack(&mut z, 4, w1);

    let w2 = pack(x, 12, 13, 14, 15)
        ^ sbox(&S5, z[7], use_ct)
        ^ sbox(&S6, z[6], use_ct)
        ^ sbox(&S7, z[5], use_ct)
        ^ sbox(&S8, z[4], use_ct)
        ^ sbox(&S5, x[9], use_ct);
    unpack(&mut z, 8, w2);

    let w3 = pack(x, 4, 5, 6, 7)
        ^ sbox(&S5, z[10], use_ct)
        ^ sbox(&S6, z[9], use_ct)
        ^ sbox(&S7, z[11], use_ct)
        ^ sbox(&S8, z[8], use_ct)
        ^ sbox(&S6, x[11], use_ct);
    unpack(&mut z, 12, w3);

    z
}

fn z_to_x(z: &[u8; 16], use_ct: bool) -> [u8; 16] {
    let mut x = [0u8; 16];
    let w0 = pack(z, 8, 9, 10, 11)
        ^ sbox(&S5, z[5], use_ct)
        ^ sbox(&S6, z[7], use_ct)
        ^ sbox(&S7, z[4], use_ct)
        ^ sbox(&S8, z[6], use_ct)
        ^ sbox(&S7, z[0], use_ct);
    unpack(&mut x, 0, w0);

    let w1 = pack(z, 0, 1, 2, 3)
        ^ sbox(&S5, x[0], use_ct)
        ^ sbox(&S6, x[2], use_ct)
        ^ sbox(&S7, x[1], use_ct)
        ^ sbox(&S8, x[3], use_ct)
        ^ sbox(&S8, z[2], use_ct);
    unpack(&mut x, 4, w1);

    let w2 = pack(z, 4, 5, 6, 7)
        ^ sbox(&S5, x[7], use_ct)
        ^ sbox(&S6, x[6], use_ct)
        ^ sbox(&S7, x[5], use_ct)
        ^ sbox(&S8, x[4], use_ct)
        ^ sbox(&S5, z[1], use_ct);
    unpack(&mut x, 8, w2);

    let w3 = pack(z, 12, 13, 14, 15)
        ^ sbox(&S5, x[10], use_ct)
        ^ sbox(&S6, x[9], use_ct)
        ^ sbox(&S7, x[11], use_ct)
        ^ sbox(&S8, x[8], use_ct)
        ^ sbox(&S6, z[3], use_ct);
    unpack(&mut x, 12, w3);

    x
}

fn extract_z_a(z: &[u8; 16], use_ct: bool) -> [u32; 4] {
    [
        sbox(&S5, z[8], use_ct)
            ^ sbox(&S6, z[9], use_ct)
            ^ sbox(&S7, z[7], use_ct)
            ^ sbox(&S8, z[6], use_ct)
            ^ sbox(&S5, z[2], use_ct),
        sbox(&S5, z[10], use_ct)
            ^ sbox(&S6, z[11], use_ct)
            ^ sbox(&S7, z[5], use_ct)
            ^ sbox(&S8, z[4], use_ct)
            ^ sbox(&S6, z[6], use_ct),
        sbox(&S5, z[12], use_ct)
            ^ sbox(&S6, z[13], use_ct)
            ^ sbox(&S7, z[3], use_ct)
            ^ sbox(&S8, z[2], use_ct)
            ^ sbox(&S7, z[9], use_ct),
        sbox(&S5, z[14], use_ct)
            ^ sbox(&S6, z[15], use_ct)
            ^ sbox(&S7, z[1], use_ct)
            ^ sbox(&S8, z[0], use_ct)
            ^ sbox(&S8, z[12], use_ct),
    ]
}

fn extract_x_a(x: &[u8; 16], use_ct: bool) -> [u32; 4] {
    [
        sbox(&S5, x[3], use_ct)
            ^ sbox(&S6, x[2], use_ct)
            ^ sbox(&S7, x[12], use_ct)
            ^ sbox(&S8, x[13], use_ct)
            ^ sbox(&S5, x[8], use_ct),
        sbox(&S5, x[1], use_ct)
            ^ sbox(&S6, x[0], use_ct)
            ^ sbox(&S7, x[14], use_ct)
            ^ sbox(&S8, x[15], use_ct)
            ^ sbox(&S6, x[13], use_ct),
        sbox(&S5, x[7], use_ct)
            ^ sbox(&S6, x[6], use_ct)
            ^ sbox(&S7, x[8], use_ct)
            ^ sbox(&S8, x[9], use_ct)
            ^ sbox(&S7, x[3], use_ct),
        sbox(&S5, x[5], use_ct)
            ^ sbox(&S6, x[4], use_ct)
            ^ sbox(&S7, x[10], use_ct)
            ^ sbox(&S8, x[11], use_ct)
            ^ sbox(&S8, x[7], use_ct),
    ]
}

fn extract_z_b(z: &[u8; 16], use_ct: bool) -> [u32; 4] {
    [
        sbox(&S5, z[3], use_ct)
            ^ sbox(&S6, z[2], use_ct)
            ^ sbox(&S7, z[12], use_ct)
            ^ sbox(&S8, z[13], use_ct)
            ^ sbox(&S5, z[9], use_ct),
        sbox(&S5, z[1], use_ct)
            ^ sbox(&S6, z[0], use_ct)
            ^ sbox(&S7, z[14], use_ct)
            ^ sbox(&S8, z[15], use_ct)
            ^ sbox(&S6, z[12], use_ct),
        sbox(&S5, z[7], use_ct)
            ^ sbox(&S6, z[6], use_ct)
            ^ sbox(&S7, z[8], use_ct)
            ^ sbox(&S8, z[9], use_ct)
            ^ sbox(&S7, z[2], use_ct),
        sbox(&S5, z[5], use_ct)
            ^ sbox(&S6, z[4], use_ct)
            ^ sbox(&S7, z[10], use_ct)
            ^ sbox(&S8, z[11], use_ct)
            ^ sbox(&S8, z[6], use_ct),
    ]
}

fn extract_x_b(x: &[u8; 16], use_ct: bool) -> [u32; 4] {
    [
        sbox(&S5, x[8], use_ct)
            ^ sbox(&S6, x[9], use_ct)
            ^ sbox(&S7, x[7], use_ct)
            ^ sbox(&S8, x[6], use_ct)
            ^ sbox(&S5, x[3], use_ct),
        sbox(&S5, x[10], use_ct)
            ^ sbox(&S6, x[11], use_ct)
            ^ sbox(&S7, x[5], use_ct)
            ^ sbox(&S8, x[4], use_ct)
            ^ sbox(&S6, x[7], use_ct),
        sbox(&S5, x[12], use_ct)
            ^ sbox(&S6, x[13], use_ct)
            ^ sbox(&S7, x[3], use_ct)
            ^ sbox(&S8, x[2], use_ct)
            ^ sbox(&S7, x[8], use_ct),
        sbox(&S5, x[14], use_ct)
            ^ sbox(&S6, x[15], use_ct)
            ^ sbox(&S7, x[1], use_ct)
            ^ sbox(&S8, x[0], use_ct)
            ^ sbox(&S8, x[13], use_ct),
    ]
}

fn round_f(data: u32, km: u32, kr: u8, round: usize, use_ct: bool) -> u32 {
    // CAST cycles through three different mixing formulas. The modulo on the
    // round index is the exact RFC rule for selecting F1 / F2 / F3.
    let i = match round % 3 {
        0 => km.wrapping_add(data).rotate_left(kr as u32),
        1 => (km ^ data).rotate_left(kr as u32),
        _ => km.wrapping_sub(data).rotate_left(kr as u32),
    };
    let [ia, ib, ic, id] = i.to_be_bytes();
    match round % 3 {
        0 => (sbox(&S1, ia, use_ct) ^ sbox(&S2, ib, use_ct))
            .wrapping_sub(sbox(&S3, ic, use_ct))
            .wrapping_add(sbox(&S4, id, use_ct)),
        1 => {
            (sbox(&S1, ia, use_ct).wrapping_sub(sbox(&S2, ib, use_ct)))
                .wrapping_add(sbox(&S3, ic, use_ct))
                ^ sbox(&S4, id, use_ct)
        }
        _ => ((sbox(&S1, ia, use_ct).wrapping_add(sbox(&S2, ib, use_ct))) ^ sbox(&S3, ic, use_ct))
            .wrapping_sub(sbox(&S4, id, use_ct)),
    }
}

#[derive(Clone, Copy)]
struct Subkeys {
    km: [u32; 16],
    kr: [u8; 16],
    rounds: usize,
}

fn expand_subkeys(key: &[u8], use_ct: bool) -> Subkeys {
    assert!(
        (5..=16).contains(&key.len()),
        "CAST-128 key length must be 5..=16 bytes, got {}",
        key.len()
    );

    let mut x = [0u8; 16];
    x[..key.len()].copy_from_slice(key);
    // Short keys are right-padded with zeros and switch to 12 rounds at 80
    // bits and below, exactly as RFC 2144 specifies for CAST5-nn variants.
    let rounds = if key.len() * 8 <= 80 { 12 } else { 16 };

    let mut k = [0u32; 32];
    let mut offset = 0usize;

    for _ in 0..2 {
        // Each x/z cycle emits 16 of the RFC's intermediate K words; the
        // first half becomes masking subkeys, the second half rotation subkeys.
        let z = x_to_z(&x, use_ct);
        k[offset..offset + 4].copy_from_slice(&extract_z_a(&z, use_ct));
        x = z_to_x(&z, use_ct);
        k[offset + 4..offset + 8].copy_from_slice(&extract_x_a(&x, use_ct));
        let z = x_to_z(&x, use_ct);
        k[offset + 8..offset + 12].copy_from_slice(&extract_z_b(&z, use_ct));
        x = z_to_x(&z, use_ct);
        k[offset + 12..offset + 16].copy_from_slice(&extract_x_b(&x, use_ct));
        offset += 16;
    }

    let mut km = [0u32; 16];
    let mut kr = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        km[i] = k[i];
        kr[i] = (k[16 + i] & 0x1f) as u8;
        i += 1;
    }

    Subkeys { km, kr, rounds }
}

fn cast_encrypt(block: &[u8; 8], subkeys: &Subkeys, use_ct: bool) -> [u8; 8] {
    let mut l = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut r = u32::from_be_bytes(block[4..8].try_into().unwrap());

    let mut i = 0usize;
    while i < subkeys.rounds {
        // Standard Feistel step: the right half becomes the next left half,
        // and the previous left half is mixed with F(right, subkey).
        let new_l = r;
        let new_r = l ^ round_f(r, subkeys.km[i], subkeys.kr[i], i, use_ct);
        l = new_l;
        r = new_r;
        i += 1;
    }

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&r.to_be_bytes());
    out[4..8].copy_from_slice(&l.to_be_bytes());
    out
}

fn cast_decrypt(block: &[u8; 8], subkeys: &Subkeys, use_ct: bool) -> [u8; 8] {
    let mut l = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut r = u32::from_be_bytes(block[4..8].try_into().unwrap());

    let mut idx = subkeys.rounds;
    while idx > 0 {
        idx -= 1;
        // Decryption is the same Feistel structure with the round keys applied
        // in reverse order.
        let new_l = r;
        let new_r = l ^ round_f(r, subkeys.km[idx], subkeys.kr[idx], idx, use_ct);
        l = new_l;
        r = new_r;
    }

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&r.to_be_bytes());
    out[4..8].copy_from_slice(&l.to_be_bytes());
    out
}

pub struct Cast128 {
    subkeys: Subkeys,
}

impl Cast128 {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            subkeys: expand_subkeys(key, false),
        }
    }

    pub fn with_key_bytes(key: &[u8]) -> Self {
        Self {
            subkeys: expand_subkeys(key, false),
        }
    }

    pub fn with_key_bytes_wiping(key: &mut [u8]) -> Self {
        let out = Self::with_key_bytes(key);
        zeroize_slice(key);
        out
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        zeroize_slice(key);
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        cast_encrypt(block, &self.subkeys, false)
    }

    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        cast_decrypt(block, &self.subkeys, false)
    }
}

impl BlockCipher for Cast128 {
    const BLOCK_LEN: usize = 8;

    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let ct = self.encrypt_block(arr);
        block.copy_from_slice(&ct);
    }

    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let pt = self.decrypt_block(arr);
        block.copy_from_slice(&pt);
    }
}

impl Drop for Cast128 {
    fn drop(&mut self) {
        zeroize_slice(&mut self.subkeys.km);
        zeroize_slice(&mut self.subkeys.kr);
    }
}

pub struct Cast128Ct {
    subkeys: Subkeys,
}

impl Cast128Ct {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            subkeys: expand_subkeys(key, true),
        }
    }

    pub fn with_key_bytes(key: &[u8]) -> Self {
        Self {
            subkeys: expand_subkeys(key, true),
        }
    }

    pub fn with_key_bytes_wiping(key: &mut [u8]) -> Self {
        let out = Self::with_key_bytes(key);
        zeroize_slice(key);
        out
    }

    pub fn new_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::new(key);
        zeroize_slice(key);
        out
    }

    pub fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        cast_encrypt(block, &self.subkeys, true)
    }

    pub fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        cast_decrypt(block, &self.subkeys, true)
    }
}

impl BlockCipher for Cast128Ct {
    const BLOCK_LEN: usize = 8;

    fn encrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let ct = self.encrypt_block(arr);
        block.copy_from_slice(&ct);
    }

    fn decrypt(&self, block: &mut [u8]) {
        let arr: &[u8; 8] = (&*block).try_into().expect("wrong block length");
        let pt = self.decrypt_block(arr);
        block.copy_from_slice(&pt);
    }
}

impl Drop for Cast128Ct {
    fn drop(&mut self) {
        zeroize_slice(&mut self.subkeys.km);
        zeroize_slice(&mut self.subkeys.kr);
    }
}

pub type Cast5 = Cast128;
pub type Cast5Ct = Cast128Ct;

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    }

    #[test]
    fn cast128_128bit_kat() {
        let key: [u8; 16] = decode_hex("0123456712345678234567893456789A")
            .try_into()
            .unwrap();
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("238B4FE5847E44B2").try_into().unwrap();
        let cipher = Cast128::new(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::new(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }

    #[test]
    fn cast128_80bit_kat() {
        let key = decode_hex("01234567123456782345");
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("EB6A711A2C02271B").try_into().unwrap();
        let cipher = Cast128::with_key_bytes(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::with_key_bytes(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }

    #[test]
    fn cast128_40bit_kat() {
        let key = decode_hex("0123456712");
        let pt: [u8; 8] = decode_hex("0123456789ABCDEF").try_into().unwrap();
        let ct: [u8; 8] = decode_hex("7AC816D16E9B302E").try_into().unwrap();
        let cipher = Cast128::with_key_bytes(&key);
        assert_eq!(cipher.encrypt_block(&pt), ct);
        assert_eq!(cipher.decrypt_block(&ct), pt);
        let cipher_ct = Cast128Ct::with_key_bytes(&key);
        assert_eq!(cipher_ct.encrypt_block(&pt), ct);
        assert_eq!(cipher_ct.decrypt_block(&ct), pt);
    }
}
