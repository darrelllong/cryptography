//! `CTR_DRBG` from NIST SP 800-90A Rev. 1 (§ 10.2.1) over AES-256 without a
//! derivation function, generic over the AES-256 implementation.
//!
//! # Instantiation parameters
//!
//! The parameters are those of SP 800-90A Rev. 1 Table 3 for AES-256:
//!
//! - block cipher: AES-256 (`keylen` = 256 bits, `outlen` = 128 bits);
//! - derivation function: not used, so `seedlen` = `keylen` + `outlen` = 384
//!   bits (48 bytes), no nonce is consumed, and the entropy input must carry
//!   the full `seedlen` on its own;
//! - security strength: 256 bits;
//! - `max_number_of_bits_per_request` = 2^19 (64 KiB per `generate`);
//! - `reseed_interval` = 2^48 requests;
//! - `max_additional_input_length` = `seedlen` (the no-df bound).
//!
//! # Which AES
//!
//! [`CtrDrbg`] takes the AES-256 type as its parameter and two aliases name
//! the choices: [`CtrDrbgAes256`] runs on the T-table [`Aes256`], whose
//! table indices are the DRBG's secret key and counter, so its timing is
//! data-dependent; [`CtrDrbgAes256Ct`] runs on [`Aes256Ct`], whose S-box is
//! a boolean circuit with no secret-dependent memory access. The two produce
//! identical output for identical inputs; only the cost and the side-channel
//! profile differ. The DRBG calls only `Block_Encrypt`, so it keys a
//! forward-only schedule and never builds the inverse one.
//!
//! # Scope
//!
//! This is the DRBG mechanism of § 10.2.1 (instantiate, reseed, generate,
//! uninstantiate-on-drop) and nothing more of SP 800-90A:
//!
//! - no entropy source: the caller supplies `seedlen` bytes of already
//!   conditioned seed material to [`CtrDrbg::new`] and [`CtrDrbg::reseed`],
//!   formed as § 10.2.1.3.1 steps 1-3 and § 10.2.1.4.1 steps 1-3 form it
//!   (entropy input XOR the zero-padded personalization string or additional
//!   input; with no personalization string it is the entropy input itself);
//! - no prediction resistance: `generate` never reseeds on its own, it stops
//!   (panics) once the reseed interval is exhausted;
//! - no health tests (§ 11.3) and no internal-state handle table (§ 9);
//! - no security-strength or derivation-function negotiation: every
//!   instance is the single configuration above.
//!
//! # Fork safety
//!
//! DRBG state is process-local. After `fork()`, parent and child hold
//! identical state and will generate identical output until one of them
//! reseeds. Callers that fork must reseed in the child before generating any
//! further output.

use crate::ciphers::aes::encrypt_only::{Aes256CtEncryptor, Aes256Encryptor};
use crate::ct::zeroize_slice;
use crate::{Aes256, Aes256Ct, Csprng};

/// `keylen` in bytes (SP 800-90A Rev. 1 Table 3, AES-256).
const KEY_LEN: usize = 32;
/// `outlen` in bytes: the AES block.
const BLOCK_LEN: usize = 16;
/// `seedlen` in bytes when no derivation function is used.
const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;
/// `max_number_of_bits_per_request` = 2^19 bits, as bytes.
const MAX_REQUEST_BYTES: usize = 1 << 16;
/// `reseed_interval`, in `generate` requests.
const RESEED_INTERVAL: u64 = 1 << 48;

/// `V = (V + 1) mod 2^outlen` (§ 10.2.1.2 step 2.1, § 10.2.1.5.1 step 4.1).
#[inline]
fn increment_be(counter: &mut [u8; BLOCK_LEN]) {
    for b in counter.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            break;
        }
    }
}

mod private {
    use super::{BLOCK_LEN, KEY_LEN};

    /// What the DRBG needs of its block cipher: keying a forward-only
    /// schedule, and `Block_Encrypt`. Private so that the set of ciphers
    /// stays the approved one.
    pub trait Sealed {
        /// The keyed, encrypt-only schedule; it wipes itself on drop.
        type Keyed;
        fn key(key: &[u8; KEY_LEN]) -> Self::Keyed;
        fn encrypt(keyed: &Self::Keyed, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN];
    }
}

/// The AES-256 implementation behind a [`CtrDrbg`].
///
/// SP 800-90A Rev. 1 approves `CTR_DRBG` over AES only (Table 3; TDEA has
/// since been withdrawn), so this trait is sealed: it is implemented for
/// [`Aes256`] (T-table, variable-time) and [`Aes256Ct`] (constant-time) and
/// cannot be implemented outside the crate.
pub trait CtrDrbgCipher: private::Sealed {}

impl private::Sealed for Aes256 {
    type Keyed = Aes256Encryptor;
    fn key(key: &[u8; KEY_LEN]) -> Self::Keyed {
        Aes256Encryptor::new(key)
    }
    fn encrypt(keyed: &Self::Keyed, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        keyed.encrypt_block(block)
    }
}
impl CtrDrbgCipher for Aes256 {}

impl private::Sealed for Aes256Ct {
    type Keyed = Aes256CtEncryptor;
    fn key(key: &[u8; KEY_LEN]) -> Self::Keyed {
        Aes256CtEncryptor::new(key)
    }
    fn encrypt(keyed: &Self::Keyed, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        keyed.encrypt_block(block)
    }
}
impl CtrDrbgCipher for Aes256Ct {}

/// `CTR_DRBG` with AES-256 and no derivation function (SP 800-90A Rev. 1
/// § 10.2.1), on the AES-256 implementation `C`.
///
/// The internal state is `(Key, V, reseed_counter)` as in § 10.2.1.1; `Key`
/// is held as its expanded forward schedule. All of it is wiped on drop.
pub struct CtrDrbg<C: CtrDrbgCipher> {
    key: C::Keyed,
    v: [u8; BLOCK_LEN],
    reseed_counter: u64,
}

/// `CTR_DRBG` on the T-table [`Aes256`].
///
/// Variable-time: the T-table indices are the DRBG's secret key and counter.
/// Produces exactly the output of [`CtrDrbgAes256Ct`] for the same inputs.
pub type CtrDrbgAes256 = CtrDrbg<Aes256>;

/// `CTR_DRBG` on the constant-time [`Aes256Ct`].
///
/// No secret-dependent memory access or branch in the block cipher; slower
/// than [`CtrDrbgAes256`], with which it agrees bit for bit.
pub type CtrDrbgAes256Ct = CtrDrbg<Aes256Ct>;

impl<C: CtrDrbgCipher> CtrDrbg<C> {
    /// Instantiate from `seedlen` = 48 bytes of seed material
    /// (§ 10.2.1.3.1, the no-df instantiate algorithm).
    ///
    /// `seed_material` is the value of § 10.2.1.3.1 step 3: the entropy input
    /// (full `seedlen`, already conditioned) XOR the zero-padded
    /// personalization string, or the entropy input alone when there is no
    /// personalization string. This constructor performs steps 4-7: `Key` and
    /// `V` start at zero, one `CTR_DRBG_Update` absorbs the seed material,
    /// and the reseed counter is set to 1.
    #[must_use]
    pub fn new(seed_material: &[u8; SEED_LEN]) -> Self {
        let mut out = Self {
            key: C::key(&[0u8; KEY_LEN]),
            v: [0u8; BLOCK_LEN],
            reseed_counter: 1,
        };
        out.update(seed_material);
        out
    }

    /// Instantiate as [`new`](Self::new) does, then wipe the caller's seed
    /// buffer, so the seed does not stay live once the DRBG has absorbed it.
    pub fn new_wiping(seed_material: &mut [u8; SEED_LEN]) -> Self {
        let out = Self::new(seed_material);
        zeroize_slice(seed_material.as_mut_slice());
        out
    }

    /// Instantiate from `seedlen` bytes of entropy input and a
    /// personalization string (§ 10.2.1.3.1 steps 1-3, then
    /// [`new`](Self::new)).
    ///
    /// Without a derivation function the instantiate algorithm zero-pads the
    /// personalization string to `seedlen` (step 2) and XORs it into the
    /// entropy input (step 3); that is the seed material `new` absorbs. An
    /// empty string leaves the entropy input as it is. The XORed copy is
    /// wiped before returning.
    ///
    /// # Panics
    ///
    /// Panics if `personalization_string` is longer than 48 bytes
    /// (`max_personalization_string_length` = `seedlen` without a derivation
    /// function, § 10.2.1 Table 3).
    #[must_use]
    pub fn instantiate(entropy_input: &[u8; SEED_LEN], personalization_string: &[u8]) -> Self {
        let mut seed_material = *entropy_input;
        xor_padded(
            &mut seed_material,
            personalization_string,
            "personalization string",
        );
        let out = Self::new(&seed_material);
        zeroize_slice(seed_material.as_mut_slice());
        out
    }

    /// Reseed from `seedlen` bytes of fresh entropy input and additional
    /// input (§ 10.2.1.4.1 steps 1-3, then [`reseed`](Self::reseed)): the
    /// additional input is zero-padded to `seedlen` and XORed into the
    /// entropy input, and the XORed copy is wiped before returning.
    ///
    /// # Panics
    ///
    /// Panics if `additional_input` is longer than 48 bytes
    /// (`max_additional_input_length` = `seedlen` without a derivation
    /// function, § 10.2.1 Table 3).
    pub fn reseed_with_additional_input(
        &mut self,
        entropy_input: &[u8; SEED_LEN],
        additional_input: &[u8],
    ) {
        let mut seed_material = *entropy_input;
        xor_padded(&mut seed_material, additional_input, "additional input");
        self.reseed(&seed_material);
        zeroize_slice(seed_material.as_mut_slice());
    }

    /// Reseed from 48 bytes of fresh seed material (§ 10.2.1.4.1, the no-df
    /// reseed algorithm).
    ///
    /// `seed_material` is the value of § 10.2.1.4.1 step 3: fresh entropy
    /// input XOR the zero-padded additional input, or the entropy input alone.
    /// Steps 4-5 run here: one `CTR_DRBG_Update`, then the reseed counter
    /// returns to 1.
    pub fn reseed(&mut self, seed_material: &[u8; SEED_LEN]) {
        self.update(seed_material);
        self.reseed_counter = 1;
    }

    /// Reseed as [`reseed`](Self::reseed) does, then wipe the caller's seed
    /// buffer.
    pub fn reseed_wiping(&mut self, seed_material: &mut [u8; SEED_LEN]) {
        self.reseed(seed_material);
        zeroize_slice(seed_material.as_mut_slice());
    }

    /// Generate `out.len()` bytes (§ 10.2.1.5.1, the no-df generate
    /// algorithm), optionally mixing in additional input.
    ///
    /// `additional_input` may be up to `seedlen` = 48 bytes; a shorter value
    /// is zero-padded to `seedlen` (step 2.1) before it updates the state
    /// (step 2.2) and is used again in the final update (step 6). `None`, and
    /// an empty slice, mean no additional input: step 2 then supplies
    /// `0^seedlen` for the final update and there is no step-2.2 update. This
    /// is the reading the NIST DRBG Validation System vectors take, where an
    /// empty `AdditionalInput` field is the no-input case.
    ///
    /// # Panics
    ///
    /// Panics if `additional_input` is longer than 48 bytes
    /// (`max_additional_input_length` without a derivation function), if
    /// `out.len()` exceeds `max_number_of_bits_per_request` (2^19 bits, 64
    /// KiB), or if the reseed counter has passed the reseed interval of 2^48
    /// requests without a [`reseed`](Self::reseed) (step 1: the standard's
    /// "reseed required" indication).
    pub fn generate(&mut self, out: &mut [u8], additional_input: Option<&[u8]>) {
        // Step 1.
        assert!(
            self.reseed_counter <= RESEED_INTERVAL,
            "CTR_DRBG reseed required"
        );
        assert!(out.len() <= MAX_REQUEST_BYTES, "CTR_DRBG request too large");

        // Step 2: `padded` is the additional input at seedlen, or 0^seedlen.
        let mut padded = [0u8; SEED_LEN];
        if let Some(data) = additional_input.filter(|data| !data.is_empty()) {
            assert!(
                data.len() <= SEED_LEN,
                "CTR_DRBG additional input exceeds seedlen"
            );
            padded[..data.len()].copy_from_slice(data); // 2.1
            self.update(&padded); // 2.2
        }

        // Steps 3-5: V+1, Block_Encrypt, take the leftmost requested bytes.
        let mut offset = 0usize;
        while offset < out.len() {
            increment_be(&mut self.v);
            let block = C::encrypt(&self.key, &self.v);
            let take = (out.len() - offset).min(BLOCK_LEN);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }

        // Steps 6-7.
        self.update(&padded);
        self.reseed_counter += 1;
        zeroize_slice(padded.as_mut_slice());
    }

    /// Current reseed counter: 1 after instantiation or reseed, then one
    /// more per `generate` request. `generate` refuses to run once it exceeds
    /// 2^48.
    #[must_use]
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// `CTR_DRBG_Update` (§ 10.2.1.2): `temp` = `seedlen` bytes of
    /// `Block_Encrypt(Key, V+1) || Block_Encrypt(Key, V+2) || ...` under the
    /// current key, XOR `provided_data`; then `Key` = the leftmost `keylen`
    /// bytes and `V` = the rightmost `outlen` bytes. Callers always supply
    /// `seedlen` bytes, so `provided_data` is not optional here.
    fn update(&mut self, provided_data: &[u8; SEED_LEN]) {
        let mut temp = [0u8; SEED_LEN];
        for chunk in temp.chunks_exact_mut(BLOCK_LEN) {
            increment_be(&mut self.v);
            chunk.copy_from_slice(&C::encrypt(&self.key, &self.v));
        }
        for (t, d) in temp.iter_mut().zip(provided_data.iter()) {
            *t ^= *d;
        }
        let mut new_key = [0u8; KEY_LEN];
        new_key.copy_from_slice(&temp[..KEY_LEN]);
        self.key = C::key(&new_key);
        self.v.copy_from_slice(&temp[KEY_LEN..]);
        zeroize_slice(new_key.as_mut_slice());
        zeroize_slice(temp.as_mut_slice());
    }
}

impl<C: CtrDrbgCipher> Csprng for CtrDrbg<C> {
    /// Fills `out` of any length by issuing successive `generate` calls of at
    /// most the SP 800-90A per-request maximum (2^16 bytes) each.
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(MAX_REQUEST_BYTES) {
            self.generate(chunk, None);
        }
    }
}

impl<C: CtrDrbgCipher> Drop for CtrDrbg<C> {
    /// Uninstantiate (§ 9.4): `Key` wipes itself as its schedule drops; `V`
    /// and the counter are wiped here.
    fn drop(&mut self) {
        zeroize_slice(self.v.as_mut_slice());
        self.reseed_counter = 0;
    }
}

/// XOR `input`, zero-padded to `seedlen`, into `seed` (§ 10.2.1.3.1 steps 2-3
/// and § 10.2.1.4.1 steps 2-3).
fn xor_padded(seed: &mut [u8; SEED_LEN], input: &[u8], what: &str) {
    assert!(
        input.len() <= SEED_LEN,
        "CTR_DRBG {what} longer than seedlen ({} > {SEED_LEN} bytes)",
        input.len()
    );
    for (byte, extra) in seed.iter_mut().zip(input) {
        *byte ^= extra;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiate_without_personalization_is_new() {
        let entropy = seed(0x10);
        let mut a = CtrDrbgAes256::instantiate(&entropy, &[]);
        let mut b = CtrDrbgAes256::new(&entropy);
        let (mut out_a, mut out_b) = ([0u8; 64], [0u8; 64]);
        a.generate(&mut out_a, None);
        b.generate(&mut out_b, None);
        assert_eq!(out_a, out_b);
    }

    #[test]
    /// § 10.2.1.3.1 step 2 pads on the right: `temp = temp || 0^(seedlen −
    /// len(temp))`, so a 20-byte string reaches bytes 0..20 of the entropy
    /// input and bytes 20..48 are XORed with zero.
    fn instantiate_xors_the_zero_padded_personalization_string() {
        let entropy = seed(0x20);
        let personalization = [0xA5u8; 20];
        let mut padded = [0u8; SEED_LEN];
        padded[..20].copy_from_slice(&personalization);
        let mut expected_seed = entropy;
        for (byte, extra) in expected_seed.iter_mut().zip(padded) {
            *byte ^= extra;
        }
        let mut left_padded = [0u8; SEED_LEN];
        left_padded[SEED_LEN - 20..].copy_from_slice(&personalization);
        assert_ne!(padded, left_padded);
        let mut a = CtrDrbgAes256::instantiate(&entropy, &personalization);
        let mut b = CtrDrbgAes256::new(&expected_seed);
        let (mut out_a, mut out_b) = ([0u8; 64], [0u8; 64]);
        a.generate(&mut out_a, None);
        b.generate(&mut out_b, None);
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn reseed_with_additional_input_xors_the_zero_padded_input() {
        let entropy = seed(0x30);
        let fresh = seed(0x40);
        let additional = [0x5Au8; 48];
        let mut expected_seed = fresh;
        for (byte, extra) in expected_seed.iter_mut().zip(additional) {
            *byte ^= extra;
        }
        let mut a = CtrDrbgAes256::new(&entropy);
        let mut b = CtrDrbgAes256::new(&entropy);
        a.reseed_with_additional_input(&fresh, &additional);
        b.reseed(&expected_seed);
        assert_eq!(a.reseed_counter(), 1);
        let (mut out_a, mut out_b) = ([0u8; 64], [0u8; 64]);
        a.generate(&mut out_a, None);
        b.generate(&mut out_b, None);
        assert_eq!(out_a, out_b);
    }

    #[test]
    #[should_panic(expected = "personalization string longer than seedlen")]
    fn instantiate_refuses_a_personalization_string_over_seedlen() {
        let _ = CtrDrbgAes256::instantiate(&seed(0), &[0u8; SEED_LEN + 1]);
    }

    /// NIST CAVP `drbgvectors_no_reseed/CTR_DRBG.rsp` (CAVS 14.3), first
    /// `[AES-256 no df]` group, COUNT = 0: EntropyInput and ReturnedBits.
    const CAVS_COUNT0_SEED: [u8; 48] = [
        0xdf, 0x5d, 0x73, 0xfa, 0xa4, 0x68, 0x64, 0x9e, 0xdd, 0xa3, 0x3b, 0x5c, 0xca, 0x79, 0xb0,
        0xb0, 0x56, 0x00, 0x41, 0x9c, 0xcb, 0x7a, 0x87, 0x9d, 0xdf, 0xec, 0x9d, 0xb3, 0x2e, 0xe4,
        0x94, 0xe5, 0x53, 0x1b, 0x51, 0xde, 0x16, 0xa3, 0x0f, 0x76, 0x92, 0x62, 0x47, 0x4c, 0x73,
        0xbe, 0xc0, 0x10,
    ];
    const CAVS_COUNT0_RETURNED: [u8; 64] = [
        0xd1, 0xc0, 0x7c, 0xd9, 0x5a, 0xf8, 0xa7, 0xf1, 0x10, 0x12, 0xc8, 0x4c, 0xe4, 0x8b, 0xb8,
        0xcb, 0x87, 0x18, 0x9e, 0x99, 0xd4, 0x0f, 0xcc, 0xb1, 0x77, 0x1c, 0x61, 0x9b, 0xdf, 0x82,
        0xab, 0x22, 0x80, 0xb1, 0xdc, 0x2f, 0x25, 0x81, 0xf3, 0x91, 0x64, 0xf7, 0xac, 0x0c, 0x51,
        0x04, 0x94, 0xb3, 0xa4, 0x3c, 0x41, 0xb7, 0xdb, 0x17, 0x51, 0x4c, 0x87, 0xb1, 0x07, 0xae,
        0x79, 0x3e, 0x01, 0xc5,
    ];

    fn seed(fill: u8) -> [u8; SEED_LEN] {
        core::array::from_fn(|i| fill.wrapping_add(u8::try_from(i).expect("index fits in u8")))
    }

    /// The DRBGVS call sequence for the no-reseed file: instantiate,
    /// generate (discarded), generate (compared).
    fn cavs_count0<C: CtrDrbgCipher>() -> [u8; 64] {
        let mut drbg = CtrDrbg::<C>::new(&CAVS_COUNT0_SEED);
        let mut discard = [0u8; 64];
        drbg.generate(&mut discard, None);
        let mut out = [0u8; 64];
        drbg.generate(&mut out, None);
        out
    }

    #[test]
    fn nist_cavs_count0_no_df_kat() {
        assert_eq!(cavs_count0::<Aes256>(), CAVS_COUNT0_RETURNED);
    }

    #[test]
    fn nist_cavs_count0_no_df_kat_ct() {
        assert_eq!(cavs_count0::<Aes256Ct>(), CAVS_COUNT0_RETURNED);
    }

    /// The two AES implementations must give the same stream through every
    /// operation: instantiate, generate with and without additional input,
    /// reseed, and generate again.
    #[test]
    fn table_and_ct_instantiations_agree() {
        let mut fast = CtrDrbgAes256::new(&seed(0x10));
        let mut slow = CtrDrbgAes256Ct::new(&seed(0x10));
        let additional = seed(0xa0);
        for (i, extra) in [None, Some(&additional[..]), Some(&additional[..7]), None]
            .into_iter()
            .enumerate()
        {
            let mut a = vec![0u8; 5 + 13 * i];
            let mut b = a.clone();
            fast.generate(&mut a, extra);
            slow.generate(&mut b, extra);
            assert_eq!(a, b, "generate #{i}");
        }
        fast.reseed(&seed(0x33));
        slow.reseed(&seed(0x33));
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        fast.fill_bytes(&mut a);
        slow.fill_bytes(&mut b);
        assert_eq!(a, b);
    }

    /// `Csprng::fill_bytes` must serve any length: over the SP 800-90A
    /// per-request limit it issues several `generate` calls, and the output
    /// equals what those calls produce back to back.
    #[test]
    fn fill_bytes_spans_the_per_request_limit() {
        let seed = [0x42u8; 48];
        let mut big = vec![0u8; MAX_REQUEST_BYTES + 5];
        CtrDrbgAes256::new(&seed).fill_bytes(&mut big);

        let mut reference = CtrDrbgAes256::new(&seed);
        let mut first = vec![0u8; MAX_REQUEST_BYTES];
        let mut second = [0u8; 5];
        reference.generate(&mut first, None);
        reference.generate(&mut second, None);
        assert_eq!(&big[..MAX_REQUEST_BYTES], &first[..]);
        assert_eq!(&big[MAX_REQUEST_BYTES..], &second[..]);
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = CtrDrbgAes256::new(&seed(0));
        let mut b = CtrDrbgAes256::new(&seed(0));
        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        a.fill_bytes(&mut out_a);
        b.fill_bytes(&mut out_b);
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn additional_input_changes_stream() {
        let add = seed(0xff);
        let mut plain = CtrDrbgAes256::new(&seed(0));
        let mut mixed = CtrDrbgAes256::new(&seed(0));
        let mut out_plain = [0u8; 32];
        let mut out_mixed = [0u8; 32];
        plain.generate(&mut out_plain, None);
        mixed.generate(&mut out_mixed, Some(&add));
        assert_ne!(out_plain, out_mixed);
    }

    /// § 10.2.1.5.1 step 2.1: additional input shorter than `seedlen` is
    /// zero-padded, so a short input and its explicitly padded form give the
    /// same output, and a short input differs from no input.
    #[test]
    fn short_additional_input_is_zero_padded_to_seedlen() {
        let add = seed(0x5a);
        for n in [1usize, 15, 16, 17, 31, 32, 47] {
            let mut padded = [0u8; SEED_LEN];
            padded[..n].copy_from_slice(&add[..n]);

            let mut short = CtrDrbgAes256::new(&seed(7));
            let mut full = CtrDrbgAes256::new(&seed(7));
            let mut none = CtrDrbgAes256::new(&seed(7));
            let mut out_short = [0u8; 48];
            let mut out_full = [0u8; 48];
            let mut out_none = [0u8; 48];
            short.generate(&mut out_short, Some(&add[..n]));
            full.generate(&mut out_full, Some(&padded));
            none.generate(&mut out_none, None);
            assert_eq!(out_short, out_full, "n = {n}");
            assert_ne!(out_short, out_none, "n = {n}");

            // The padded value is also what step 6 folds back in, so the
            // streams stay equal afterwards.
            short.generate(&mut out_short, None);
            full.generate(&mut out_full, None);
            assert_eq!(out_short, out_full, "n = {n}, next request");
        }
    }

    /// An empty additional input is the no-input case (as in the DRBGVS
    /// files, where `AdditionalInput` is empty for `AdditionalInputLen = 0`).
    #[test]
    fn empty_additional_input_equals_none() {
        let mut a = CtrDrbgAes256::new(&seed(9));
        let mut b = CtrDrbgAes256::new(&seed(9));
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        a.generate(&mut out_a, Some(&[]));
        b.generate(&mut out_b, None);
        assert_eq!(out_a, out_b);
    }

    #[test]
    #[should_panic(expected = "additional input exceeds seedlen")]
    fn additional_input_longer_than_seedlen_is_refused() {
        let mut drbg = CtrDrbgAes256::new(&seed(1));
        let mut out = [0u8; 16];
        drbg.generate(&mut out, Some(&[0u8; SEED_LEN + 1]));
    }

    #[test]
    #[should_panic(expected = "request too large")]
    fn oversized_request_is_refused() {
        let mut drbg = CtrDrbgAes256::new(&seed(1));
        let mut out = vec![0u8; MAX_REQUEST_BYTES + 1];
        drbg.generate(&mut out, None);
    }

    /// § 10.2.1.3.1 step 7, § 10.2.1.4.1 step 5, § 10.2.1.5.1 step 7: the
    /// counter is 1 after instantiate and after reseed, and each request adds
    /// one.
    #[test]
    fn reseed_counter_tracks_requests_and_reseeds() {
        let mut drbg = CtrDrbgAes256::new(&seed(2));
        assert_eq!(drbg.reseed_counter(), 1);
        let mut out = [0u8; 8];
        for expected in 2..6 {
            drbg.generate(&mut out, None);
            assert_eq!(drbg.reseed_counter(), expected);
        }
        drbg.generate(&mut out, Some(&seed(3)));
        assert_eq!(drbg.reseed_counter(), 6);
        drbg.reseed(&seed(4));
        assert_eq!(drbg.reseed_counter(), 1);
        drbg.fill_bytes(&mut [0u8; MAX_REQUEST_BYTES + 1]);
        assert_eq!(drbg.reseed_counter(), 3, "two requests for 64 KiB + 1");
        drbg.reseed_wiping(&mut seed(5));
        assert_eq!(drbg.reseed_counter(), 1);
    }

    /// `reseed_wiping` reseeds exactly as `reseed` does and erases the
    /// caller's buffer.
    #[test]
    fn reseed_wiping_matches_reseed_and_erases_the_seed() {
        let mut reference = CtrDrbgAes256::new(&seed(0x80));
        let mut wiping = CtrDrbgAes256::new(&seed(0x80));
        let mut scratch = [0u8; 8];
        reference.generate(&mut scratch, None);
        wiping.generate(&mut scratch, None);

        let fresh = seed(0xc0);
        let mut buffer = fresh;
        reference.reseed(&fresh);
        wiping.reseed_wiping(&mut buffer);
        assert_eq!(buffer, [0u8; SEED_LEN]);

        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        reference.fill_bytes(&mut a);
        wiping.fill_bytes(&mut b);
        assert_eq!(a, b);

        // And the reseed took effect: a DRBG that was not reseeded diverges.
        let mut stale = CtrDrbgAes256::new(&seed(0x80));
        stale.generate(&mut scratch, None);
        let mut c = [0u8; 64];
        stale.fill_bytes(&mut c);
        assert_ne!(a, c);
    }
}
