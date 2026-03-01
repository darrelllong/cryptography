//! SHA-3 (Keccak-f[1600]) from FIPS 202.
//!
//! This module implements the fixed-output SHA-3 family:
//!
//! - `Sha3_224`
//! - `Sha3_256`
//! - `Sha3_384`
//! - `Sha3_512`
//!
//! The core is the Keccak sponge over the 1600-bit permutation with the SHA-3
//! domain-separation suffix `0x06`.

use super::{Digest, Xof};

const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

#[inline(always)]
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        for y in 0..5 {
            let row = 5 * y;
            for x in 0..5 {
                state[row + x] = b[row + x] ^ ((!b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)]);
            }
        }

        state[0] ^= rc;
    }
}

#[inline(always)]
fn absorb_block<const RATE: usize>(state: &mut [u64; 25], block: &[u8; RATE]) {
    debug_assert_eq!(RATE % 8, 0, "Keccak rate must be lane-aligned");
    let lanes = RATE / 8;
    let mut i = 0usize;
    while i < lanes {
        let lane = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        state[i] ^= lane;
        i += 1;
    }
    keccak_f1600(state);
}

#[derive(Clone)]
struct Keccak<const RATE: usize> {
    state: [u64; 25],
    block: [u8; RATE],
    pos: usize,
}

#[derive(Clone)]
struct KeccakSponge<const RATE: usize> {
    state: [u64; 25],
    block: [u8; RATE],
    offset: usize,
}

#[derive(Clone)]
enum XofState<const RATE: usize> {
    Absorbing(Keccak<RATE>),
    Squeezing(KeccakSponge<RATE>),
}

impl<const RATE: usize> XofState<RATE> {
    fn zeroize(&mut self) {
        match self {
            XofState::Absorbing(inner) => {
                crate::ct::zeroize_slice(inner.state.as_mut_slice());
                crate::ct::zeroize_slice(inner.block.as_mut_slice());
                inner.pos = 0;
            }
            XofState::Squeezing(sponge) => {
                crate::ct::zeroize_slice(sponge.state.as_mut_slice());
                crate::ct::zeroize_slice(sponge.block.as_mut_slice());
                sponge.offset = 0;
            }
        }
    }
}

#[inline(always)]
fn state_to_rate_bytes<const RATE: usize>(state: &[u64; 25]) -> [u8; RATE] {
    let mut rate_bytes = [0u8; RATE];
    let lanes = RATE / 8;
    let mut i = 0usize;
    while i < lanes {
        rate_bytes[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        i += 1;
    }
    rate_bytes
}

impl<const RATE: usize> Keccak<RATE> {
    fn new() -> Self {
        Self {
            state: [0u64; 25],
            block: [0u8; RATE],
            pos: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (RATE - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == RATE {
                absorb_block(&mut self.state, &self.block);
                self.block = [0u8; RATE];
                self.pos = 0;
            }
        }
    }

    fn finalize_sponge(mut self, suffix: u8) -> KeccakSponge<RATE> {
        self.block[self.pos] ^= suffix;
        self.block[RATE - 1] ^= 0x80;
        absorb_block(&mut self.state, &self.block);
        KeccakSponge {
            block: state_to_rate_bytes(&self.state),
            state: self.state,
            offset: 0,
        }
    }

    fn finalize<const OUT: usize>(self) -> [u8; OUT] {
        let mut sponge = self.finalize_sponge(0x06);
        let mut out = [0u8; OUT];
        sponge.squeeze(&mut out);
        out
    }

    fn finalize_into_reset<const OUT: usize>(&mut self, suffix: u8, out: &mut [u8; OUT]) {
        self.block[self.pos] ^= suffix;
        self.block[RATE - 1] ^= 0x80;
        absorb_block(&mut self.state, &self.block);

        let mut sponge: KeccakSponge<RATE> = KeccakSponge {
            block: state_to_rate_bytes(&self.state),
            state: self.state,
            offset: 0,
        };
        sponge.squeeze(out);

        crate::ct::zeroize_slice(sponge.state.as_mut_slice());
        crate::ct::zeroize_slice(sponge.block.as_mut_slice());
        sponge.offset = 0;

        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
    }
}

impl<const RATE: usize> KeccakSponge<RATE> {
    fn squeeze(&mut self, out: &mut [u8]) {
        let mut produced = 0usize;
        while produced < out.len() {
            if self.offset == RATE {
                keccak_f1600(&mut self.state);
                self.block = state_to_rate_bytes(&self.state);
                self.offset = 0;
            }

            let take = (out.len() - produced).min(RATE - self.offset);
            out[produced..produced + take]
                .copy_from_slice(&self.block[self.offset..self.offset + take]);
            produced += take;
            self.offset += take;
        }
    }
}

macro_rules! define_sha3 {
    ($name:ident, $rate:expr, $out_len:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Keccak<$rate>,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $rate;
            pub const OUTPUT_LEN: usize = $out_len;

            pub fn new() -> Self {
                Self {
                    inner: Keccak::new(),
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            pub fn finalize(self) -> [u8; $out_len] {
                self.inner.finalize()
            }

            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = $rate;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                $name {
                    inner: Keccak::new(),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(self, out: &mut [u8]) {
                assert_eq!(out.len(), $out_len, "wrong digest length");
                let digest = self.inner.finalize::<$out_len>();
                out.copy_from_slice(&digest);
            }

            fn finalize_reset(&mut self, out: &mut [u8]) {
                let out: &mut [u8; $out_len] = out.try_into().expect("wrong digest length");
                self.inner.finalize_into_reset::<$out_len>(0x06, out);
            }

            fn zeroize(&mut self) {
                crate::ct::zeroize_slice(self.inner.state.as_mut_slice());
                crate::ct::zeroize_slice(self.inner.block.as_mut_slice());
                self.inner.pos = 0;
            }
        }
    };
}

define_sha3!(Sha3_224, 144, 28);
define_sha3!(Sha3_256, 136, 32);
define_sha3!(Sha3_384, 104, 48);
define_sha3!(Sha3_512, 72, 64);

macro_rules! define_shake {
    ($name:ident, $rate:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: XofState<$rate>,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $rate;

            pub fn new() -> Self {
                Self {
                    inner: XofState::Absorbing(Keccak::new()),
                }
            }

            pub fn digest(data: &[u8], out: &mut [u8]) {
                let mut xof = Self::new();
                xof.update(data);
                xof.squeeze(out);
            }
        }

        impl Xof for $name {
            fn update(&mut self, data: &[u8]) {
                match &mut self.inner {
                    XofState::Absorbing(inner) => inner.update(data),
                    XofState::Squeezing(_) => panic!("cannot absorb after squeezing"),
                }
            }

            fn squeeze(&mut self, out: &mut [u8]) {
                if let XofState::Absorbing(_) = self.inner {
                    let prev =
                        core::mem::replace(&mut self.inner, XofState::Absorbing(Keccak::new()));
                    let sponge = match prev {
                        XofState::Absorbing(inner) => inner.finalize_sponge(0x1f),
                        XofState::Squeezing(sponge) => sponge,
                    };
                    self.inner = XofState::Squeezing(sponge);
                }

                match &mut self.inner {
                    XofState::Absorbing(_) => unreachable!(),
                    XofState::Squeezing(sponge) => sponge.squeeze(out),
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

define_shake!(Shake128, 168);
define_shake!(Shake256, 136);

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    #[test]
    fn sha3_224_empty() {
        assert_eq!(
            hex(&Sha3_224::digest(b"")),
            "6b4e03423667dbb73b6e15454f0eb1ab".to_owned() + "d4597f9a1b078e3f5b5a6bc7"
        );
    }

    #[test]
    fn sha3_256_empty() {
        assert_eq!(
            hex(&Sha3_256::digest(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662".to_owned() + "f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn sha3_256_abc_streaming() {
        let mut h = Sha3_256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            hex(&h.finalize()),
            "3a985da74fe225b2045c172d6bd390bd".to_owned() + "855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_384_empty() {
        assert_eq!(
            hex(&Sha3_384::digest(b"")),
            "0c63a75b845e4f7d01107d852e4c2485".to_owned()
                + "c51a50aaaa94fc61995e71bbee983a2a"
                + "c3713831264adb47fb6bd1e058d5f004"
        );
    }

    #[test]
    fn sha3_512_empty() {
        assert_eq!(
            hex(&Sha3_512::digest(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e".to_owned()
                + "97c982164fe25859e0d1dcc1475c80a6"
                + "15b2123af1f5f94c11e3e9402c3ac558"
                + "f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn shake128_empty_32() {
        let mut out = [0u8; 32];
        Shake128::digest(b"", &mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853e".to_owned() + "d73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn shake128_abc_streaming_32() {
        let mut xof = Shake128::new();
        xof.update(b"a");
        xof.update(b"b");
        xof.update(b"c");
        let mut out = [0u8; 32];
        xof.squeeze(&mut out);
        assert_eq!(
            hex(&out),
            "5881092dd818bf5cf8a3ddb793fbcba7".to_owned() + "4097d5c526a6d35f97b83351940f2cc8"
        );
    }

    #[test]
    fn shake128_chunked_squeeze_matches_one_shot() {
        let mut one_shot = Shake128::new();
        one_shot.update(b"abc");
        let mut full = [0u8; 64];
        one_shot.squeeze(&mut full);

        let mut chunked = Shake128::new();
        chunked.update(b"abc");
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        chunked.squeeze(&mut left);
        chunked.squeeze(&mut right);

        assert_eq!([left.as_slice(), right.as_slice()].concat(), full);
    }

    #[test]
    fn shake256_empty_64() {
        let mut out = [0u8; 64];
        Shake256::digest(b"", &mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb24".to_owned()
                + "3fcd52ea62b81b82b50c27646ed5762f"
                + "d75dc4ddd8c0f200cb05019d67b592f6"
                + "fc821c49479ab48640292eacb3b7c4be"
        );
    }
}
