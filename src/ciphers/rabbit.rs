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
//!
//! Usage rules from RFC 4503 §3: one key encrypts at most 2^64 128-bit blocks
//! (§3.1), and a generator run without the IV setup must never be reset under
//! the same key (§3.2). See [`Rabbit::new`] and [`Rabbit::without_iv`].
//!
//! Timing: the state update is arithmetic only (no table lookups), but the
//! `g`-function squares a secret 32-bit sum into 64 bits, so its running time
//! is constant only where the hardware multiplier's is.

// Rabbit counter increments `A[i]` from RFC 4503 §2.5 (derived from the
// fractional part of sqrt(pi) in the original Rabbit specification).
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

        // `k` is the key split into its eight 16-bit subkeys.
        crate::ct::zeroize_slice(k.as_mut_slice());
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
        let mut old_c = self.c;
        let mut carry = self.carry;
        for i in 0..8 {
            let sum = u64::from(old_c[i]) + u64::from(A[i]) + u64::from(carry);
            self.c[i] = sum as u32;
            carry = (sum >> 32) as u32;
        }
        self.carry = carry;

        let mut g = [0u32; 8];
        for (i, gi) in g.iter_mut().enumerate() {
            *gi = g_func(self.x[i], self.c[i]);
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

        // `old_c` copies the secret counter words and `g` the next state's
        // inputs; neither may outlive the step.
        crate::ct::zeroize_slice(old_c.as_mut_slice());
        crate::ct::zeroize_slice(g.as_mut_slice());
    }

    #[inline]
    fn keystream_block(&mut self) -> [u8; 16] {
        self.next_state();

        let mut s = [
            self.x[0] ^ (self.x[5] >> 16) ^ (self.x[3] << 16),
            self.x[2] ^ (self.x[7] >> 16) ^ (self.x[5] << 16),
            self.x[4] ^ (self.x[1] >> 16) ^ (self.x[7] << 16),
            self.x[6] ^ (self.x[3] >> 16) ^ (self.x[1] << 16),
        ];

        // RFC 4503 publishes Rabbit test vectors in octet form using I2OSP, so
        // the stream is emitted most-significant word first in big-endian.
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&s[3].to_be_bytes());
        out[4..8].copy_from_slice(&s[2].to_be_bytes());
        out[8..12].copy_from_slice(&s[1].to_be_bytes());
        out[12..16].copy_from_slice(&s[0].to_be_bytes());
        crate::ct::zeroize_slice(s.as_mut_slice());
        out
    }
}

/// Rabbit stream cipher.
///
/// The `new` constructor applies both the key setup and the RFC IV setup.
/// `without_iv` leaves the cipher in the key-only state used by the RFC's
/// key-setup test vectors.
///
/// RFC 4503 §3.1: one key is good for at most 2^64 128-bit keystream blocks;
/// past that the key must be replaced, whether or not IVs are rotated. The
/// instance keeps no block count; that budget is the caller's.
pub struct Rabbit {
    core: RabbitCore,
    block: [u8; 16],
    offset: usize,
}

impl Rabbit {
    /// Create Rabbit from a 128-bit key and 64-bit IV (RFC 4503 §2.3 key
    /// setup followed by the §2.4 IV setup).
    ///
    /// RFC 4503 §3.2: no IV may be reused under the same key.
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

    /// Create Rabbit from a 128-bit key without applying the optional IV setup
    /// (RFC 4503 §2.3 key setup only).
    ///
    /// RFC 4503 §3.2: a generator run without the IV setup "must never be
    /// reset under the same key". Every instance built by this constructor
    /// from a given key produces the same keystream, so a key given to it
    /// may be used for exactly one instance, for one continuous stream. Use
    /// [`Rabbit::new`] with a fresh IV wherever the cipher is re-synchronised.
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
    ///
    /// The same one-instance-per-key rule as [`Rabbit::without_iv`] applies.
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
    use crate::test_utils::decode_hex;

    fn array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = decode_hex(hex);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    /// RFC 4503 Appendix A.1, "Testing without IV Setup": the three keys and
    /// their first three keystream blocks S[0], S[1], S[2].
    #[test]
    fn rfc4503_appendix_a1_without_iv_setup() {
        let cases = [
            (
                "00000000000000000000000000000000",
                "B15754F036A5D6ECF56B45261C4AF702\
                 88E8D815C59C0C397B696C4789C68AA7\
                 F416A1C3700CD451DA68D1881673D696",
            ),
            (
                "912813292E3D36FE3BFC62F1DC51C3AC",
                "3D2DF3C83EF627A1E97FC38487E2519C\
                 F576CD61F4405B8896BF53AA8554FC19\
                 E5547473FBDB43508AE53B20204D4C5E",
            ),
            (
                "8395741587E0C733E9E9AB01C09B0043",
                "0CB10DCDA041CDAC32EB5CFD02D0609B\
                 95FC9FCA0F17015A7B7092114CFF3EAD\
                 9649E5DE8BFC7F3F924147AD3A947428",
            ),
        ];
        for (key, expected) in cases {
            let mut rabbit = Rabbit::without_iv(&array::<16>(key));
            let mut out = [0u8; 48];
            rabbit.fill(&mut out);
            assert_eq!(out.as_slice(), decode_hex(expected).as_slice(), "key {key}");
        }
    }

    /// RFC 4503 Appendix A.2, "Testing with IV Setup": the all-zero master key
    /// under the three published IVs, first three blocks S[0], S[1], S[2].
    #[test]
    fn rfc4503_appendix_a2_with_iv_setup() {
        let key = [0u8; 16];
        let cases = [
            (
                "0000000000000000",
                "C6A7275EF85495D87CCD5D376705B7ED\
                 5F29A6AC04F5EFD47B8F293270DC4A8D\
                 2ADE822B29DE6C1EE52BDB8A47BF8F66",
            ),
            (
                "C373F575C1267E59",
                "1FCD4EB9580012E2E0DCCC9222017D6D\
                 A75F4E10D12125017B2499FFED936F2E\
                 EBC112C393E738392356BDD012029BA7",
            ),
            (
                "A6EB561AD2F41727",
                "445AD8C805858DBF70B6AF23A151104D\
                 96C8F27947F42C5BAEAE67C6ACC35B03\
                 9FCBFC895FA71C17313DF034F01551CB",
            ),
        ];
        for (iv, expected) in cases {
            let mut rabbit = Rabbit::new(&key, &array::<8>(iv));
            let mut out = [0u8; 48];
            rabbit.fill(&mut out);
            assert_eq!(out.as_slice(), decode_hex(expected).as_slice(), "iv {iv}");
        }
    }

    /// The keystream is one continuous byte stream across `fill` calls of any
    /// length, including many calls shorter than one 16-byte block.
    #[test]
    fn chunked_fill_matches_one_shot() {
        let key = array::<16>("912813292E3D36FE3BFC62F1DC51C3AC");
        let iv = array::<8>("C373F575C1267E59");
        let mut one_shot = [0u8; 48];
        Rabbit::new(&key, &iv).fill(&mut one_shot);
        for lens in [[1usize; 48].as_slice(), &[3, 1, 1, 1, 15, 1, 26]] {
            let mut chunked = [0u8; 48];
            let mut rabbit = Rabbit::new(&key, &iv);
            let mut off = 0;
            for &len in lens {
                rabbit.fill(&mut chunked[off..off + len]);
                off += len;
            }
            assert_eq!(off, 48);
            assert_eq!(chunked, one_shot, "chunking {lens:?}");
        }
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

    /// `new_wiping` zeroes the caller's key and IV and yields the same stream
    /// as `new`.
    #[test]
    fn new_wiping_zeroes_inputs_and_matches_new() {
        let key = array::<16>("8395741587E0C733E9E9AB01C09B0043");
        let iv = array::<8>("A6EB561AD2F41727");
        let mut expected = [0u8; 40];
        Rabbit::new(&key, &iv).fill(&mut expected);

        let mut key_buf = key;
        let mut iv_buf = iv;
        let mut rabbit = Rabbit::new_wiping(&mut key_buf, &mut iv_buf);
        assert_eq!(key_buf, [0u8; 16]);
        assert_eq!(iv_buf, [0u8; 8]);
        let mut out = [0u8; 40];
        rabbit.fill(&mut out);
        assert_eq!(out, expected);
    }

    /// `without_iv_wiping` zeroes the caller's key and yields the same stream
    /// as `without_iv`.
    #[test]
    fn without_iv_wiping_zeroes_key_and_matches_without_iv() {
        let key = array::<16>("912813292E3D36FE3BFC62F1DC51C3AC");
        let mut expected = [0u8; 40];
        Rabbit::without_iv(&key).fill(&mut expected);

        let mut key_buf = key;
        let mut rabbit = Rabbit::without_iv_wiping(&mut key_buf);
        assert_eq!(key_buf, [0u8; 16]);
        let mut out = [0u8; 40];
        rabbit.fill(&mut out);
        assert_eq!(out, expected);
    }
}
