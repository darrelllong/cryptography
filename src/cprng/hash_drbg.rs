//! `Hash_DRBG` over SHA-256 (NIST SP 800-90A Rev. 1 §10.1.1).
//!
//! The working state is `V` and `C`, each `seedlen` = 440 bits (§10.1 Table 2),
//! and the reseed counter. `V`, `C`, the Hashgen counter and every addend are
//! unsigned big-endian integers, and every addition is modulo 2^seedlen,
//! carried out in rump's `BigUint` and reduced to the low 440 bits.
//!
//! One call of [`HashDrbg::generate`] is one §10.1.1.4 Generate: Hashgen
//! produces ⌈n/256⌉ blocks for an `n`-bit request, and `V` is updated once.
//! Splitting a request into two calls changes the output. The mechanism has
//! backtracking resistance (§8.8): the update is one-way in SHA-256, so a later
//! compromise of the state does not reveal earlier output. It has no
//! prediction resistance unless the caller reseeds with fresh entropy.

use super::{DrbgError, MAX_REQUEST_BYTES, MIN_ENTROPY_BYTES, MIN_NONCE_BYTES, RESEED_INTERVAL};
use crate::ct::zeroize_slice;
use crate::hash::Digest;
use crate::{Csprng, Sha256};
use rump::BigUint;

/// `seedlen` for SHA-256, in bytes (440 bits).
pub const SEEDLEN: usize = 55;
const SEEDLEN_BITS: usize = SEEDLEN * 8;
/// SHA-256 output length, in bytes.
const OUTLEN: usize = 32;
/// SHA-256 blocks `Hash_df` concatenates for a `seedlen` output (§10.3.1
/// step 2: `len = ⌈no_of_bits_to_return / outlen⌉`).
const HASH_DF_BLOCKS: usize = SEEDLEN.div_ceil(OUTLEN);

/// Prefix of `Hash_df` when deriving `C` (§10.1.1.2 step 4, §10.1.1.3 step 4:
/// `C = Hash_df(0x00 ‖ V)`).
const C_PREFIX: u8 = 0x00;
/// Prefix of the reseed seed material (§10.1.1.3 step 1: `0x01 ‖ V ‖
/// entropy_input ‖ additional_input`).
const RESEED_PREFIX: u8 = 0x01;
/// Prefix of the additional-input hash (§10.1.1.4 step 2.1: `w = Hash(0x02 ‖
/// V ‖ additional_input)`).
const ADDITIONAL_INPUT_PREFIX: u8 = 0x02;
/// Prefix of the state-update hash (§10.1.1.4 step 4: `H = Hash(0x03 ‖ V)`).
const UPDATE_PREFIX: u8 = 0x03;

/// `Hash_DRBG` instantiated with SHA-256.
pub struct HashDrbg {
    v: [u8; SEEDLEN],
    c: [u8; SEEDLEN],
    reseed_counter: u64,
}

/// SHA-256 of the concatenation of `parts`, without concatenating them.
fn sha256(parts: &[&[u8]]) -> [u8; OUTLEN] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    let mut out = [0u8; OUTLEN];
    hash.finalize_into(&mut out);
    out
}

/// `Hash_df(input, 440)` (§10.3.1): the leftmost 440 bits of
/// `Hash(1 ‖ 440 ‖ input) ‖ Hash(2 ‖ 440 ‖ input)`, with the counter as one
/// byte and the bit count as four big-endian bytes.
fn hash_df(input: &[&[u8]]) -> [u8; SEEDLEN] {
    let bits = u32::try_from(SEEDLEN_BITS)
        .expect("seedlen fits a u32")
        .to_be_bytes();
    let mut temp = [0u8; HASH_DF_BLOCKS * OUTLEN];
    for (counter, block) in (1u8..).zip(temp.chunks_exact_mut(OUTLEN)) {
        let mut hash = Sha256::new();
        hash.update(&[counter]);
        hash.update(&bits);
        for part in input {
            hash.update(part);
        }
        hash.finalize_into(block);
    }
    let mut out = [0u8; SEEDLEN];
    out.copy_from_slice(&temp[..SEEDLEN]);
    zeroize_slice(temp.as_mut_slice());
    out
}

/// `acc = (acc + Σ addends) mod 2^seedlen`, each addend big-endian, so a
/// shorter one is aligned to the least significant end.
fn add_mod_seedlen(acc: &mut [u8; SEEDLEN], addends: &[&[u8]]) {
    let mut sum = BigUint::from_be_bytes(acc);
    for addend in addends {
        sum += &BigUint::from_be_bytes(addend);
    }
    let mut bytes = sum.low_bits(SEEDLEN_BITS).to_be_bytes_padded(SEEDLEN);
    acc.copy_from_slice(&bytes);
    zeroize_slice(bytes.as_mut_slice());
}

impl HashDrbg {
    /// `Hash_DRBG_Instantiate_algorithm` (§10.1.1.2): `seed_material =
    /// entropy_input ‖ nonce ‖ personalization_string`, `V = Hash_df(seed_material)`,
    /// `C = Hash_df(0x00 ‖ V)`, `reseed_counter = 1`.
    ///
    /// # Errors
    ///
    /// [`DrbgError::InputTooShort`] when `entropy_input` is shorter than 32
    /// bytes or `nonce` shorter than 16 (256-bit security strength).
    pub fn instantiate(
        entropy_input: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
    ) -> Result<Self, DrbgError> {
        if entropy_input.len() < MIN_ENTROPY_BYTES || nonce.len() < MIN_NONCE_BYTES {
            return Err(DrbgError::InputTooShort);
        }
        let v = hash_df(&[entropy_input, nonce, personalization_string]);
        let c = hash_df(&[&[C_PREFIX], &v]);
        Ok(Self {
            v,
            c,
            reseed_counter: 1,
        })
    }

    /// `Hash_DRBG_Reseed_algorithm` (§10.1.1.3): `V = Hash_df(0x01 ‖ V ‖
    /// entropy_input ‖ additional_input)`, `C = Hash_df(0x00 ‖ V)`,
    /// `reseed_counter = 1`.
    ///
    /// # Errors
    ///
    /// [`DrbgError::InputTooShort`] when `entropy_input` is shorter than 32
    /// bytes; the state is then unchanged.
    pub fn reseed(
        &mut self,
        entropy_input: &[u8],
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        if entropy_input.len() < MIN_ENTROPY_BYTES {
            return Err(DrbgError::InputTooShort);
        }
        let mut v = hash_df(&[&[RESEED_PREFIX], &self.v, entropy_input, additional_input]);
        self.v.copy_from_slice(&v);
        zeroize_slice(v.as_mut_slice());
        let mut c = hash_df(&[&[C_PREFIX], &self.v]);
        self.c.copy_from_slice(&c);
        zeroize_slice(c.as_mut_slice());
        self.reseed_counter = 1;
        Ok(())
    }

    /// `Hash_DRBG_Generate_algorithm` (§10.1.1.4), one request of
    /// `out.len()` bytes:
    ///
    /// 1. refuse when `reseed_counter > reseed_interval`;
    /// 2. with nonempty `additional_input`, `w = Hash(0x02 ‖ V ‖
    ///    additional_input)` and `V = V + w`;
    /// 3. `Hashgen`: hash `data = V`, `V + 1`, ... and keep the leftmost
    ///    `out.len()` bytes;
    /// 4. `H = Hash(0x03 ‖ V)`, `V = V + H + C + reseed_counter`, and the
    ///    counter advances.
    ///
    /// An empty `additional_input` is the standard's Null.
    ///
    /// # Errors
    ///
    /// [`DrbgError::ReseedRequired`] past the reseed interval and
    /// [`DrbgError::RequestTooLarge`] above 2^19 bits; the state and `out`
    /// are then unchanged.
    pub fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }
        if out.len() > MAX_REQUEST_BYTES {
            return Err(DrbgError::RequestTooLarge);
        }
        if !additional_input.is_empty() {
            let mut w = sha256(&[&[ADDITIONAL_INPUT_PREFIX], &self.v, additional_input]);
            add_mod_seedlen(&mut self.v, &[&w]);
            zeroize_slice(w.as_mut_slice());
        }
        let mut data = self.v;
        let one = [1u8];
        for chunk in out.chunks_mut(OUTLEN) {
            let mut block = sha256(&[&data]);
            chunk.copy_from_slice(&block[..chunk.len()]);
            zeroize_slice(block.as_mut_slice());
            add_mod_seedlen(&mut data, &[&one]);
        }
        zeroize_slice(data.as_mut_slice());
        let mut h = sha256(&[&[UPDATE_PREFIX], &self.v]);
        let counter = self.reseed_counter.to_be_bytes();
        let c = self.c;
        add_mod_seedlen(&mut self.v, &[&h, &c, &counter]);
        zeroize_slice(h.as_mut_slice());
        self.reseed_counter += 1;
        Ok(())
    }

    /// The reseed counter: 1 after instantiation or reseed, then one more per
    /// `generate` request.
    #[must_use]
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    #[cfg(test)]
    pub(crate) fn set_reseed_counter(&mut self, counter: u64) {
        self.reseed_counter = counter;
    }
}

impl Csprng for HashDrbg {
    /// Fill `out` with successive [`HashDrbg::generate`] requests of at most
    /// 2^16 bytes each and no additional input.
    ///
    /// # Panics
    ///
    /// Panics when the reseed interval of 2^48 requests has passed.
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(MAX_REQUEST_BYTES) {
            self.generate(chunk, &[])
                .expect("Hash_DRBG reseed required");
        }
    }
}

impl Drop for HashDrbg {
    /// Uninstantiate (§9.4): `V`, `C` and the counter are wiped.
    fn drop(&mut self) {
        zeroize_slice(self.v.as_mut_slice());
        zeroize_slice(self.c.as_mut_slice());
        self.reseed_counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (2^440 − 1) + 1 ≡ 0, a carry across rump's 64-bit limbs, and the top
    /// limb holding only 56 of the 440 bits.
    #[test]
    fn additions_are_modulo_2_pow_440() {
        let mut v = [0xffu8; SEEDLEN];
        add_mod_seedlen(&mut v, &[&[1]]);
        assert_eq!(v, [0u8; SEEDLEN]);

        let mut v = [0u8; SEEDLEN];
        v[SEEDLEN - 8..].fill(0xff);
        add_mod_seedlen(&mut v, &[&[1]]);
        let mut want = [0u8; SEEDLEN];
        want[SEEDLEN - 9] = 1;
        assert_eq!(v, want);

        let mut v = [0xffu8; SEEDLEN];
        add_mod_seedlen(&mut v, &[&[0xffu8; SEEDLEN]]);
        let mut want = [0xffu8; SEEDLEN];
        want[SEEDLEN - 1] = 0xfe;
        assert_eq!(v, want);
    }

    /// The §10.1.1.4 update adds a 32-byte, a 55-byte and an 8-byte addend,
    /// each aligned to the least significant end.
    #[test]
    fn mixed_width_addends_align_right() {
        let mut v = [0u8; SEEDLEN];
        add_mod_seedlen(
            &mut v,
            &[&[0x01u8; OUTLEN], &[0x02u8; SEEDLEN], &3u64.to_be_bytes()],
        );
        let mut want = [0x02u8; SEEDLEN];
        want[SEEDLEN - OUTLEN..].fill(0x03);
        want[SEEDLEN - 1] = 0x06;
        assert_eq!(v, want);
    }

    fn drbg() -> HashDrbg {
        let entropy: Vec<u8> = (0x00u8..0x37).collect();
        let nonce: Vec<u8> = (0x40u8..0x50).collect();
        HashDrbg::instantiate(&entropy, &nonce, &[]).expect("long enough")
    }

    /// A request at 2^48 is served and the next is refused, leaving the
    /// state and the output buffer as they were.
    #[test]
    fn reseed_interval_is_enforced_after_the_last_allowed_request() {
        let mut d = drbg();
        d.set_reseed_counter(RESEED_INTERVAL);
        let mut out = [0u8; OUTLEN];
        assert_eq!(d.generate(&mut out, &[]), Ok(()));
        let (v, counter) = (d.v, d.reseed_counter());
        let mut refused = [0xaau8; OUTLEN];
        assert_eq!(
            d.generate(&mut refused, &[]),
            Err(DrbgError::ReseedRequired)
        );
        assert_eq!(
            (d.v, d.reseed_counter(), refused),
            (v, counter, [0xaa; OUTLEN])
        );
        d.reseed(&[0x11; 32], &[]).expect("32 bytes");
        assert_eq!(d.generate(&mut out, &[]), Ok(()));
    }

    #[test]
    fn oversized_requests_and_short_inputs_are_refused() {
        let mut d = drbg();
        let mut big = vec![0u8; MAX_REQUEST_BYTES + 1];
        assert_eq!(d.generate(&mut big, &[]), Err(DrbgError::RequestTooLarge));
        assert_eq!(d.generate(&mut big[..MAX_REQUEST_BYTES], &[]), Ok(()));
        assert!(HashDrbg::instantiate(&[0; 31], &[0; 16], &[]).is_err());
        assert!(HashDrbg::instantiate(&[0; 32], &[0; 15], &[]).is_err());
        assert!(d.reseed(&[0; 31], &[]).is_err());
    }

    fn hex(text: &str) -> Vec<u8> {
        crate::test_utils::decode_hex(text)
    }

    /// Two 128-byte requests with and without additional input, from entropy
    /// input 00 01 ... 36 and nonce 40 41 ... 4f: the values the `rng-entropy`
    /// crate's `HashDrbg` produced before this mechanism moved here, from an
    /// independent replica of the §10.1.1 pseudocode, so the adapter over this
    /// type keeps its output.
    #[test]
    fn generate_matches_the_values_entropy_relies_on() {
        let mut d = drbg();
        let mut out = [0u8; 128];
        d.generate(&mut out, &[]).expect("first");
        d.generate(&mut out, &[]).expect("second");
        assert_eq!(
            out.to_vec(),
            hex(
                "55338e1e62a2de3b061dd4c932ee89d2d1b9db8192cf88db37b50106080c10e1\
                 56a147c3a0d0ba4045e2d21e39fad4e5aa155c4a19effdda2426531733b1ba59\
                 e45e3e2aef109fe85482169f3ce7182131763c05395074d127c8ee8603ff0713\
                 ae9f99215a344fb2dfea4c30e34f078d601c103300c077c5945cfdd1a1991001"
            )
        );

        let a1: Vec<u8> = (0x00u8..0x20).collect();
        let a2: Vec<u8> = (0x20u8..0x40).collect();
        let mut d = drbg();
        d.generate(&mut out, &a1).expect("first");
        d.generate(&mut out, &a2).expect("second");
        assert_eq!(
            out.to_vec(),
            hex(
                "7c23e42fbae910f79d028ad1a146c8f2fd20f13b0fe4e4f36a343aec343c1922\
                 a0e4b759736a94fa132ef5a5f0c2e0bb48915028d064c87f925462dbd2d84018\
                 6666941fc85130bea189d5afdea3be87c0c8800990b99a5966dc3ee4f1dbcac7\
                 8733e896af59437d15623c165f64011b1399e0d7c9222977fc2ef9aeacdfa23e"
            )
        );
    }

    /// Sixty-four successive 256-byte requests, the refill layout of entropy's
    /// streaming `HashDrbg`: the same digest its golden test pins.
    #[test]
    fn refills_of_256_bytes_match_entropy_stream_golden() {
        let mut d = drbg();
        let mut stream = Vec::with_capacity(64 * 256);
        let mut refill = [0u8; 256];
        for _ in 0..64 {
            d.generate(&mut refill, &[]).expect("fresh");
            stream.extend_from_slice(&refill);
        }
        assert_eq!(
            sha256(&[&stream]).to_vec(),
            hex("258cfe0eaacdb03eac051981f14a3bec4612925213adc1de394a4ab55129c9aa")
        );
        let first_word = u32::from_le_bytes(stream[..4].try_into().expect("4"));
        assert_eq!(first_word, 0x83f2_33a1);
    }

    /// One 256-byte request is eight Hashgen blocks followed by one update.
    #[test]
    fn a_256_byte_request_is_eight_hashgen_blocks() {
        let mut d = drbg();
        let v = d.v;
        let mut out = [0u8; 256];
        d.generate(&mut out, &[]).expect("fresh");
        let mut data = v;
        for block in out.chunks(OUTLEN) {
            assert_eq!(block, sha256(&[&data]));
            add_mod_seedlen(&mut data, &[&[1]]);
        }
    }
}
