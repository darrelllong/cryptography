//! SHA-2 family from FIPS 180-4.

use super::Digest;

const K32: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const K64: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[inline(always)]
fn compress32(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K32[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[inline(always)]
fn compress64(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K64[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[derive(Clone)]
struct Sha2_32Core {
    state: [u32; 8],
    block: [u8; 64],
    pos: usize,
    bit_len: u64,
}

impl Sha2_32Core {
    fn new(iv: [u32; 8]) -> Self {
        Self {
            state: iv,
            block: [0u8; 64],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 64 {
                compress32(&mut self.state, &self.block);
                self.block = [0u8; 64];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(512);
            }
        }
    }

    fn finalize<const OUT: usize>(mut self) -> [u8; OUT] {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u64) * 8);
        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 56 {
            self.block[self.pos..].fill(0);
            compress32(&mut self.state, &self.block);
            self.block = [0u8; 64];
            self.pos = 0;
        }

        self.block[self.pos..56].fill(0);
        self.block[56..].copy_from_slice(&self.bit_len.to_be_bytes());
        compress32(&mut self.state, &self.block);

        let mut full = [0u8; 32];
        for (chunk, word) in full.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        let mut out = [0u8; OUT];
        out.copy_from_slice(&full[..OUT]);
        out
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

#[derive(Clone)]
struct Sha2_64Core {
    state: [u64; 8],
    block: [u8; 128],
    pos: usize,
    bit_len: u128,
}

impl Sha2_64Core {
    fn new(iv: [u64; 8]) -> Self {
        Self {
            state: iv,
            block: [0u8; 128],
            pos: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (128 - self.pos).min(data.len());
            self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == 128 {
                compress64(&mut self.state, &self.block);
                self.block = [0u8; 128];
                self.pos = 0;
                self.bit_len = self.bit_len.wrapping_add(1024);
            }
        }
    }

    fn finalize<const OUT: usize>(mut self) -> [u8; OUT] {
        self.bit_len = self.bit_len.wrapping_add((self.pos as u128) * 8);
        self.block[self.pos] = 0x80;
        self.pos += 1;

        if self.pos > 112 {
            self.block[self.pos..].fill(0);
            compress64(&mut self.state, &self.block);
            self.block = [0u8; 128];
            self.pos = 0;
        }

        self.block[self.pos..112].fill(0);
        self.block[112..].copy_from_slice(&self.bit_len.to_be_bytes());
        compress64(&mut self.state, &self.block);

        let mut full = [0u8; 64];
        for (chunk, word) in full.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        let mut out = [0u8; OUT];
        out.copy_from_slice(&full[..OUT]);
        out
    }

    fn zeroize(&mut self) {
        crate::ct::zeroize_slice(self.state.as_mut_slice());
        crate::ct::zeroize_slice(self.block.as_mut_slice());
        self.pos = 0;
        self.bit_len = 0;
    }
}

macro_rules! define_sha2_32 {
    ($name:ident, $out_len:expr, $iv:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Sha2_32Core,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 64;
            pub const OUTPUT_LEN: usize = $out_len;

            pub fn new() -> Self {
                Self {
                    inner: Sha2_32Core::new($iv),
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            pub fn finalize(self) -> [u8; $out_len] {
                self.inner.finalize::<$out_len>()
            }

            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = 64;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                Self::new()
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(self, out: &mut [u8]) {
                assert_eq!(out.len(), $out_len, "wrong digest length");
                out.copy_from_slice(&self.inner.finalize::<$out_len>());
            }

            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

macro_rules! define_sha2_64 {
    ($name:ident, $out_len:expr, $iv:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Sha2_64Core,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 128;
            pub const OUTPUT_LEN: usize = $out_len;

            pub fn new() -> Self {
                Self {
                    inner: Sha2_64Core::new($iv),
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            pub fn finalize(self) -> [u8; $out_len] {
                self.inner.finalize::<$out_len>()
            }

            pub fn digest(data: &[u8]) -> [u8; $out_len] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Digest for $name {
            const BLOCK_LEN: usize = 128;
            const OUTPUT_LEN: usize = $out_len;

            fn new() -> Self {
                Self::new()
            }

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize_into(self, out: &mut [u8]) {
                assert_eq!(out.len(), $out_len, "wrong digest length");
                out.copy_from_slice(&self.inner.finalize::<$out_len>());
            }

            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

define_sha2_32!(
    Sha224,
    28,
    [
        0xc105_9ed8,
        0x367c_d507,
        0x3070_dd17,
        0xf70e_5939,
        0xffc0_0b31,
        0x6858_1511,
        0x64f9_8fa7,
        0xbefa_4fa4,
    ]
);

define_sha2_32!(
    Sha256,
    32,
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
);

define_sha2_64!(
    Sha384,
    48,
    [
        0xcbbb_9d5d_c105_9ed8,
        0x629a_292a_367c_d507,
        0x9159_015a_3070_dd17,
        0x152f_ecd8_f70e_5939,
        0x6733_2667_ffc0_0b31,
        0x8eb4_4a87_6858_1511,
        0xdb0c_2e0d_64f9_8fa7,
        0x47b5_481d_befa_4fa4,
    ]
);

define_sha2_64!(
    Sha512,
    64,
    [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ]
);

define_sha2_64!(
    Sha512_224,
    28,
    [
        0x8c3d_37c8_1954_4da2,
        0x73e1_9966_89dc_d4d6,
        0x1dfa_b7ae_32ff_9c82,
        0x679d_d514_582f_9fcf,
        0x0f6d_2b69_7bd4_4da8,
        0x77e3_6f73_04c4_8942,
        0x3f9d_85a8_6a1d_36c8,
        0x1112_e6ad_91d6_92a1,
    ]
);

define_sha2_64!(
    Sha512_256,
    32,
    [
        0x2231_2194_fc2b_f72c,
        0x9f55_5fa3_c84c_64c2,
        0x2393_b86b_6f53_b151,
        0x9638_7719_5940_eabd,
        0x9628_3ee2_a88e_ffe3,
        0xbe5e_1e25_5386_3992,
        0x2b01_99fc_2c85_b8aa,
        0x0eb7_2ddc_81c5_2ca2,
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    fn run_openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(stdin).ok()?;
        let out = child.wait_with_output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(out.stdout)
    }

    #[test]
    fn sha224_empty() {
        assert_eq!(
            hex(&Sha224::digest(b"")),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb924".to_owned() + "27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_streaming() {
        let mut h = Sha256::new();
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(
            hex(&h.finalize()),
            "ba7816bf8f01cfea414140de5dae2223".to_owned() + "b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_empty() {
        assert_eq!(
            hex(&Sha384::digest(b"")),
            "38b060a751ac96384cd9327eb1b1e36a".to_owned()
                + "21fdb71114be07434c0cc7bf63f6e1da"
                + "274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn sha512_empty() {
        assert_eq!(
            hex(&Sha512::digest(b"")),
            "cf83e1357eefb8bdf1542850d66d8007".to_owned()
                + "d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f"
                + "63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_224_empty() {
        assert_eq!(
            hex(&Sha512_224::digest(b"")),
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        );
    }

    #[test]
    fn sha512_256_empty() {
        assert_eq!(
            hex(&Sha512_256::digest(b"")),
            "c672b8d1ef56ed28ab87c3622c511406".to_owned() + "9bdd3ad7b8f9737498d0c01ecef0967a"
        );
    }

    #[test]
    fn sha256_matches_openssl() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let expected = match run_openssl(&["dgst", "-sha256", "-binary"], msg) {
            Some(bytes) => bytes,
            None => return,
        };
        assert_eq!(Sha256::digest(msg).as_slice(), expected.as_slice());
    }
}
