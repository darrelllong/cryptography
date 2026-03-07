//! ML-KEM (Kyber) API scaffold.
//!
//! This module currently provides:
//! - parameter-set constants for ML-KEM-512/768/1024
//! - strict typed containers for public keys, private keys, ciphertexts, and
//!   shared secrets
//! - compact wire encodings and crate-defined key blobs
//!
//! Arithmetic (`keygen` / `encaps` / `decaps`) is intentionally staged and
//! will be added in a follow-up pass against FIPS 203 and the pinned
//! `pq-crystals/kyber` reference source.

use core::fmt;

/// ML-KEM parameter sets from FIPS 203.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParameterSet {
    /// Lattice rank parameter.
    #[must_use]
    pub const fn k(self) -> usize {
        match self {
            Self::MlKem512 => 2,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 4,
        }
    }

    /// Public-key byte length.
    ///
    /// Formula: `384*k + 32`.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        384 * self.k() + 32
    }

    /// Secret-key byte length.
    ///
    /// Formula: `768*k + 96`.
    #[must_use]
    pub const fn private_key_len(self) -> usize {
        768 * self.k() + 96
    }

    /// Ciphertext byte length.
    #[must_use]
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Shared-secret length in bytes.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        let _ = self;
        32
    }

    #[must_use]
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::MlKem512 => 0x02,
            Self::MlKem768 => 0x03,
            Self::MlKem1024 => 0x04,
        }
    }

    #[must_use]
    pub(crate) const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x02 => Some(Self::MlKem512),
            0x03 => Some(Self::MlKem768),
            0x04 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

/// ML-KEM public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemPublicKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM private key.
#[derive(Clone, Eq, PartialEq)]
pub struct MlKemPrivateKey {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemCiphertext {
    params: MlKemParameterSet,
    bytes: Vec<u8>,
}

/// ML-KEM shared secret (32 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemSharedSecret {
    bytes: [u8; 32],
}

/// Namespace for ML-KEM operations.
pub struct MlKem;

impl MlKemPublicKey {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.public_key_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, bytes) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, bytes)
    }
}

impl MlKemPrivateKey {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.private_key_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn to_key_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.params.id());
        out.extend_from_slice(&self.bytes);
        out
    }

    #[must_use]
    pub fn from_key_blob(blob: &[u8]) -> Option<Self> {
        let (&id, bytes) = blob.split_first()?;
        let params = MlKemParameterSet::from_id(id)?;
        Self::from_wire_bytes(params, bytes)
    }
}

impl MlKemCiphertext {
    #[must_use]
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.params
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[must_use]
    pub fn from_wire_bytes(params: MlKemParameterSet, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != params.ciphertext_len() {
            return None;
        }
        Some(Self {
            params,
            bytes: bytes.to_vec(),
        })
    }
}

impl MlKemSharedSecret {
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut ss = [0u8; 32];
        ss.copy_from_slice(bytes);
        Some(Self { bytes: ss })
    }
}

impl MlKem {
    /// Generate an ML-KEM keypair.
    ///
    /// Arithmetic is staged and not yet implemented.
    #[must_use]
    pub fn keygen(_params: MlKemParameterSet) -> Option<(MlKemPublicKey, MlKemPrivateKey)> {
        None
    }

    /// Encapsulate to a recipient public key.
    ///
    /// Arithmetic is staged and not yet implemented.
    #[must_use]
    pub fn encaps(_public_key: &MlKemPublicKey) -> Option<(MlKemCiphertext, MlKemSharedSecret)> {
        None
    }

    /// Decapsulate a ciphertext with a private key.
    ///
    /// Arithmetic is staged and not yet implemented.
    #[must_use]
    pub fn decaps(
        _private_key: &MlKemPrivateKey,
        _ciphertext: &MlKemCiphertext,
    ) -> Option<MlKemSharedSecret> {
        None
    }
}

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKemPrivateKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_parameter_lengths_match_profiles() {
        assert_eq!(MlKemParameterSet::MlKem512.public_key_len(), 800);
        assert_eq!(MlKemParameterSet::MlKem512.private_key_len(), 1632);
        assert_eq!(MlKemParameterSet::MlKem512.ciphertext_len(), 768);

        assert_eq!(MlKemParameterSet::MlKem768.public_key_len(), 1184);
        assert_eq!(MlKemParameterSet::MlKem768.private_key_len(), 2400);
        assert_eq!(MlKemParameterSet::MlKem768.ciphertext_len(), 1088);

        assert_eq!(MlKemParameterSet::MlKem1024.public_key_len(), 1568);
        assert_eq!(MlKemParameterSet::MlKem1024.private_key_len(), 3168);
        assert_eq!(MlKemParameterSet::MlKem1024.ciphertext_len(), 1568);
    }

    #[test]
    fn public_key_wire_and_blob_roundtrip() {
        let params = MlKemParameterSet::MlKem768;
        let bytes = vec![0xA5; params.public_key_len()];
        let pk = MlKemPublicKey::from_wire_bytes(params, &bytes).expect("pk");

        let blob = pk.to_key_blob();
        let decoded = MlKemPublicKey::from_key_blob(&blob).expect("blob");
        assert_eq!(decoded, pk);
        assert!(MlKemPublicKey::from_wire_bytes(params, &bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn private_key_wire_and_blob_roundtrip() {
        let params = MlKemParameterSet::MlKem1024;
        let bytes = vec![0x5A; params.private_key_len()];
        let sk = MlKemPrivateKey::from_wire_bytes(params, &bytes).expect("sk");

        let blob = sk.to_key_blob();
        let decoded = MlKemPrivateKey::from_key_blob(&blob).expect("blob");
        assert_eq!(decoded, sk);
        assert!(MlKemPrivateKey::from_wire_bytes(params, &bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn ciphertext_wire_roundtrip() {
        let params = MlKemParameterSet::MlKem512;
        let bytes = vec![0x3C; params.ciphertext_len()];
        let ct = MlKemCiphertext::from_wire_bytes(params, &bytes).expect("ct");
        assert_eq!(ct.to_wire_bytes(), bytes);
        assert!(MlKemCiphertext::from_wire_bytes(params, &[0u8; 7]).is_none());
    }

    #[test]
    fn shared_secret_wire_roundtrip() {
        let ss_bytes = [0x11u8; 32];
        let ss = MlKemSharedSecret::from_wire_bytes(&ss_bytes).expect("ss");
        assert_eq!(ss.to_wire_bytes(), ss_bytes);
        assert!(MlKemSharedSecret::from_wire_bytes(&ss_bytes[..31]).is_none());
    }

    #[test]
    fn key_blob_rejects_unknown_profile_id() {
        let blob = vec![0xFF, 0x00];
        assert!(MlKemPublicKey::from_key_blob(&blob).is_none());
        assert!(MlKemPrivateKey::from_key_blob(&blob).is_none());
    }

    #[test]
    fn staged_arithmetic_returns_none() {
        assert!(MlKem::keygen(MlKemParameterSet::MlKem512).is_none());
    }
}
