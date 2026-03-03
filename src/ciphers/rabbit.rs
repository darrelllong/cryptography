//! Rabbit stream cipher — RFC 4503.
//!
//! Rabbit is a software-oriented 128-bit stream cipher from the eSTREAM era.
//! Its state consists of eight 32-bit state words, eight 32-bit counters, and
//! one carry bit. Each round advances the counters, runs the nonlinear
//! `g`-function on each state word plus counter, and then mixes the eight `g`
//! outputs into the next state.
//!
//! The implementation follows RFC 4503 directly:
//!
//! - 128-bit key
//! - optional 64-bit IV setup
//! - 16-byte keystream blocks
//!
//! Rabbit is naturally byte-oriented like the other stream ciphers in this
//! crate: `apply_keystream` `XOR`s the keystream into caller-owned buffers.

const A: [u32; 8] = [
    0x4D34_D34D,
    0xD34D_34D3,
    0x34D3_4D34,
    0x4D34_D34D,
    0xD34D_34D3,
    0x34D3_4D34,
    0x4D34_D34D,
    0xD34D_34D3,
];

#[inline]
fn load_u16_be(bytes: &[u8]) -> u16 {
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(bytes);
    u16::from_be_bytes(tmp)
}

#[inline]
fn load_u32_be(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(bytes);
    u32::from_be_bytes(tmp)
}

#[inline]
fn cat16(hi: u16, lo: u16) -> u32 {
    (u32::from(hi) << 16) | u32::from(lo)
}

#[inline]
fn g_func(x: u32, c: u32) -> u32 {
    let sum = u64::from(x.wrapping_add(c));
    let square = sum.wrapping_mul(sum);
    (square as u32) ^ ((square >> 32) as u32)
}

#[derive(Clone)]
struct RabbitCore {
    x: [u32; 8],
    c: [u32; 8],
    carry: u32,
}

impl RabbitCore {
    fn from_key(key: &[u8; 16]) -> Self {
        let mut k = [0u16; 8];
        for (i, chunk) in key.rchunks_exact(2).enumerate() {
            k[i] = load_u16_be(chunk);
        }

        let mut core = Self {
            x: [
                cat16(k[1], k[0]),
                cat16(k[6], k[5]),
                cat16(k[3], k[2]),
                cat16(k[0], k[7]),
                cat16(k[5], k[4]),
                cat16(k[2], k[1]),
                cat16(k[7], k[6]),
                cat16(k[4], k[3]),
            ],
            c: [
                cat16(k[4], k[5]),
                cat16(k[1], k[2]),
                cat16(k[6], k[7]),
                cat16(k[3], k[4]),
                cat16(k[0], k[1]),
                cat16(k[5], k[6]),
                cat16(k[2], k[3]),
                cat16(k[7], k[0]),
            ],
            carry: 0,
        };

        for _ in 0..4 {
            core.next_state();
        }

        for i in 0..8 {
            core.c[i] ^= core.x[(i + 4) & 7];
        }

        core
    }

    fn apply_iv(&mut self, iv: &[u8; 8]) {
        let v0 = load_u32_be(&iv[4..8]);
        let v1 = cat16(load_u16_be(&iv[0..2]), load_u16_be(&iv[4..6]));
        let v2 = load_u32_be(&iv[0..4]);
        let v3 = cat16(load_u16_be(&iv[2..4]), load_u16_be(&iv[6..8]));

        self.c[0] ^= v0;
        self.c[1] ^= v1;
        self.c[2] ^= v2;
        self.c[3] ^= v3;
        self.c[4] ^= v0;
        self.c[5] ^= v1;
        self.c[6] ^= v2;
        self.c[7] ^= v3;

        for _ in 0..4 {
            self.next_state();
        }
    }

    #[inline]
    fn next_state(&mut self) {
        let old_c = self.c;
        let mut carry = self.carry;
        for i in 0..8 {
            let sum = u64::from(old_c[i]) + u64::from(A[i]) + u64::from(carry);
            self.c[i] = sum as u32;
            carry = (sum >> 32) as u32;
        }
        self.carry = carry;

        let mut g = [0u32; 8];
        for i in 0..8 {
            g[i] = g_func(self.x[i], self.c[i]);
        }

        self.x[0] = g[0]
            .wrapping_add(g[7].rotate_left(16))
            .wrapping_add(g[6].rotate_left(16));
        self.x[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
        self.x[2] = g[2]
            .wrapping_add(g[1].rotate_left(16))
            .wrapping_add(g[0].rotate_left(16));
        self.x[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
        self.x[4] = g[4]
            .wrapping_add(g[3].rotate_left(16))
            .wrapping_add(g[2].rotate_left(16));
        self.x[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
        self.x[6] = g[6]
            .wrapping_add(g[5].rotate_left(16))
            .wrapping_add(g[4].rotate_left(16));
        self.x[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);
    }

    #[inline]
    fn keystream_block(&mut self) -> [u8; 16] {
        self.next_state();

        let s = [
            self.x[0] ^ (self.x[5] >> 16) ^ self.x[3].wrapping_shl(16),
            self.x[2] ^ (self.x[7] >> 16) ^ self.x[5].wrapping_shl(16),
            self.x[4] ^ (self.x[1] >> 16) ^ self.x[7].wrapping_shl(16),
            self.x[6] ^ (self.x[3] >> 16) ^ self.x[1].wrapping_shl(16),
        ];

        // RFC 4503 publishes Rabbit test vectors in octet form using I2OSP, so
        // the stream is emitted most-significant word first in big-endian.
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&s[3].to_be_bytes());
        out[4..8].copy_from_slice(&s[2].to_be_bytes());
        out[8..12].copy_from_slice(&s[1].to_be_bytes());
        out[12..16].copy_from_slice(&s[0].to_be_bytes());
        out
    }
}

/// Rabbit stream cipher.
///
/// The `new` constructor applies both the key setup and the RFC IV setup.
/// `without_iv` leaves the cipher in the key-only state used by the RFC's
/// key-setup test vectors.
pub struct Rabbit {
    core: RabbitCore,
    block: [u8; 16],
    offset: usize,
}

impl Rabbit {
    /// Create Rabbit from a 128-bit key and 64-bit IV.
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 8]) -> Self {
        let mut core = RabbitCore::from_key(key);
        core.apply_iv(iv);
        Self {
            core,
            block: [0u8; 16],
            offset: 16,
        }
    }

    /// Create Rabbit from a 128-bit key without applying the optional IV setup.
    #[must_use]
    pub fn without_iv(key: &[u8; 16]) -> Self {
        Self {
            core: RabbitCore::from_key(key),
            block: [0u8; 16],
            offset: 16,
        }
    }

    /// Create and wipe the caller's key and IV buffers.
    pub fn new_wiping(key: &mut [u8; 16], iv: &mut [u8; 8]) -> Self {
        let out = Self::new(key, iv);
        crate::ct::zeroize_slice(key.as_mut_slice());
        crate::ct::zeroize_slice(iv.as_mut_slice());
        out
    }

    /// Create without IV setup and wipe the caller's key buffer.
    pub fn without_iv_wiping(key: &mut [u8; 16]) -> Self {
        let out = Self::without_iv(key);
        crate::ct::zeroize_slice(key.as_mut_slice());
        out
    }

    #[inline]
    fn refill(&mut self) {
        self.block = self.core.keystream_block();
        self.offset = 0;
    }

    /// XOR the Rabbit keystream into `buf` in place.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let mut done = 0usize;
        while done < buf.len() {
            if self.offset == 16 {
                self.refill();
            }
            let take = core::cmp::min(16 - self.offset, buf.len() - done);
            for i in 0..take {
                buf[done + i] ^= self.block[self.offset + i];
            }
            self.offset += take;
            done += take;
        }
    }

    /// Fill `buf` with keystream bytes by `XORing` into the existing contents.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.apply_keystream(buf);
    }

    /// Return the next 16 bytes of keystream.
    pub fn keystream_block(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.apply_keystream(&mut out);
        out
    }
}

impl Drop for Rabbit {
    fn drop(&mut self) {
        crate::ct::zeroize_slice(self.core.x.as_mut_slice());
        crate::ct::zeroize_slice(self.core.c.as_mut_slice());
        self.core.carry = 0;
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn rabbit_zero_key_rfc_keystream() {
        let mut rabbit = Rabbit::without_iv(&[0u8; 16]);
        let mut out = [0u8; 48];
        rabbit.fill(&mut out);
        let expected = decode_hex(
            "B15754F036A5D6ECF56B45261C4AF702\
             88E8D815C59C0C397B696C4789C68AA7\
             F416A1C3700CD451DA68D1881673D696",
        );
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn rabbit_key_only_rfc_vector_two() {
        let key = decode_hex("912813292E3D36FE3BFC62F1DC51C3AC");
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(&key);
        let mut rabbit = Rabbit::without_iv(&key_arr);
        let mut out = [0u8; 48];
        rabbit.fill(&mut out);
        let expected = decode_hex(
            "3D2DF3C83EF627A1E97FC38487E2519C\
             F576CD61F4405B8896BF53AA8554FC19\
             E5547473FBDB43508AE53B20204D4C5E",
        );
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn rabbit_zero_key_zero_iv_rfc_keystream() {
        let mut rabbit = Rabbit::new(&[0u8; 16], &[0u8; 8]);
        let mut out = [0u8; 48];
        rabbit.fill(&mut out);
        let expected = decode_hex(
            "C6A7275EF85495D87CCD5D376705B7ED\
             5F29A6AC04F5EFD47B8F293270DC4A8D\
             2ADE822B29DE6C1EE52BDB8A47BF8F66",
        );
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn rabbit_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 8];
        let plain = *b"rabbit stream demo";

        let mut enc = Rabbit::new(&key, &iv);
        let mut ct = plain;
        enc.apply_keystream(&mut ct);

        let mut dec = Rabbit::new(&key, &iv);
        dec.apply_keystream(&mut ct);

        assert_eq!(ct, plain);
    }
}
