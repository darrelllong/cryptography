//! `HMAC_DRBG` over HMAC-SHA-256 (NIST SP 800-90A Rev. 1 §10.1.2).
//!
//! The working state is `Key` and `V`, each 256 bits, and the reseed counter.
//! One call of [`HmacDrbg::generate`] is one §10.1.2.5 Generate: `V` is
//! re-HMACed once per 32 output bytes and the state is updated once at the
//! end, so splitting a request into two calls changes the output. The
//! mechanism has backtracking resistance (§8.8) and no prediction resistance
//! unless the caller reseeds with fresh entropy.

use super::{DrbgError, MAX_REQUEST_BYTES, MIN_ENTROPY_BYTES, MIN_NONCE_BYTES, RESEED_INTERVAL};
use crate::ct::zeroize_slice;
use crate::{Csprng, Hmac, Sha256};

/// HMAC-SHA-256 output length, in bytes.
const OUTLEN: usize = 32;

/// `HMAC_DRBG` instantiated with HMAC-SHA-256.
pub struct HmacDrbg {
    key: [u8; OUTLEN],
    v: [u8; OUTLEN],
    reseed_counter: u64,
}

/// `HMAC(key, parts[0] ‖ parts[1] ‖ ...)`.
fn hmac(key: &[u8; OUTLEN], parts: &[&[u8]]) -> [u8; OUTLEN] {
    let mut mac = Hmac::<Sha256>::new(key);
    for part in parts {
        mac.update(part);
    }
    let mut out = [0u8; OUTLEN];
    mac.finalize_into(&mut out);
    out
}

impl HmacDrbg {
    /// `HMAC_DRBG_Update` (§10.1.2.2): `Key = HMAC(Key, V ‖ 0x00 ‖
    /// provided_data)`, `V = HMAC(Key, V)`, and, when `provided_data` is not
    /// empty, the same again with `0x01`.
    fn update(&mut self, provided_data: &[&[u8]]) {
        for (round, separator) in [0x00u8, 0x01].into_iter().enumerate() {
            if round == 1 && provided_data.iter().all(|part| part.is_empty()) {
                break;
            }
            let mut parts: Vec<&[u8]> = vec![&self.v, core::slice::from_ref(&separator)];
            parts.extend_from_slice(provided_data);
            let mut key = hmac(&self.key, &parts);
            self.key = key;
            zeroize_slice(key.as_mut_slice());
            let mut v = hmac(&self.key, &[&self.v]);
            self.v = v;
            zeroize_slice(v.as_mut_slice());
        }
    }

    /// `HMAC_DRBG_Instantiate_algorithm` (§10.1.2.3): `Key = 0x00...00`,
    /// `V = 0x01...01`, `HMAC_DRBG_Update(entropy_input ‖ nonce ‖
    /// personalization_string)`, `reseed_counter = 1`.
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
        let mut drbg = Self {
            key: [0x00; OUTLEN],
            v: [0x01; OUTLEN],
            reseed_counter: 1,
        };
        drbg.update(&[entropy_input, nonce, personalization_string]);
        Ok(drbg)
    }

    /// `HMAC_DRBG_Reseed_algorithm` (§10.1.2.4): `HMAC_DRBG_Update(
    /// entropy_input ‖ additional_input)`, `reseed_counter = 1`.
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
        self.update(&[entropy_input, additional_input]);
        self.reseed_counter = 1;
        Ok(())
    }

    /// `HMAC_DRBG_Generate_algorithm` (§10.1.2.5), one request of
    /// `out.len()` bytes:
    ///
    /// 1. refuse when `reseed_counter > reseed_interval`;
    /// 2. with nonempty `additional_input`, `HMAC_DRBG_Update(additional_input)`;
    /// 3. `V = HMAC(Key, V)` repeatedly, keeping the leftmost `out.len()`
    ///    bytes of the concatenation;
    /// 4. `HMAC_DRBG_Update(additional_input)`, and the counter advances.
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
            self.update(&[additional_input]);
        }
        for chunk in out.chunks_mut(OUTLEN) {
            let mut v = hmac(&self.key, &[&self.v]);
            self.v = v;
            zeroize_slice(v.as_mut_slice());
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(&[additional_input]);
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

impl Csprng for HmacDrbg {
    /// Fill `out` with successive [`HmacDrbg::generate`] requests of at most
    /// 2^16 bytes each and no additional input.
    ///
    /// # Panics
    ///
    /// Panics when the reseed interval of 2^48 requests has passed.
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(MAX_REQUEST_BYTES) {
            self.generate(chunk, &[])
                .expect("HMAC_DRBG reseed required");
        }
    }
}

impl Drop for HmacDrbg {
    /// Uninstantiate (§9.4): `Key`, `V` and the counter are wiped.
    fn drop(&mut self) {
        zeroize_slice(self.key.as_mut_slice());
        zeroize_slice(self.v.as_mut_slice());
        self.reseed_counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drbg() -> HmacDrbg {
        HmacDrbg::instantiate(&[0x42; 32], &[0x24; 16], &[]).expect("long enough")
    }

    /// A request at 2^48 is served and the next is refused, leaving the
    /// state and the output buffer as they were.
    #[test]
    fn reseed_interval_is_enforced_after_the_last_allowed_request() {
        let mut d = drbg();
        d.set_reseed_counter(RESEED_INTERVAL);
        let mut out = [0u8; OUTLEN];
        assert_eq!(d.generate(&mut out, &[]), Ok(()));
        let (key, v, counter) = (d.key, d.v, d.reseed_counter());
        let mut refused = [0xaau8; OUTLEN];
        assert_eq!(
            d.generate(&mut refused, &[]),
            Err(DrbgError::ReseedRequired)
        );
        assert_eq!(
            (d.key, d.v, d.reseed_counter(), refused),
            (key, v, counter, [0xaa; OUTLEN])
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
        assert!(HmacDrbg::instantiate(&[0; 31], &[0; 16], &[]).is_err());
        assert!(HmacDrbg::instantiate(&[0; 32], &[0; 15], &[]).is_err());
        assert!(d.reseed(&[0; 31], &[]).is_err());
    }

    /// Without provided data the update is one round, so a Generate with no
    /// additional input equals the equations run by hand.
    #[test]
    fn generate_without_additional_input_follows_the_equations() {
        let mut d = drbg();
        let (key, v) = (d.key, d.v);
        let mut out = [0u8; 40];
        d.generate(&mut out, &[]).expect("fresh");
        let v1 = hmac(&key, &[&v]);
        let v2 = hmac(&key, &[&v1]);
        assert_eq!(out[..32], v1);
        assert_eq!(out[32..], v2[..8]);
        let key2 = hmac(&key, &[&v2, &[0x00]]);
        let v3 = hmac(&key2, &[&v2]);
        assert_eq!((d.key, d.v), (key2, v3));
    }
}
