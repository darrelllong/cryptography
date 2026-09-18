//! Hybrid Public Key Encryption (RFC 9180) over DHKEM(X25519, HKDF-SHA256).
//!
//! HPKE is the authenticated construction the raw schemes in this crate are
//! not: [`ElGamal`](crate::public_key::elgamal) and its relatives encrypt a
//! group element and say so, while this encrypts a message under a recipient's
//! public key, with associated data, a key schedule that binds the context,
//! and a documented refusal when authentication fails.
//!
//! What is implemented here is one cipher suite family — the KEM of §7.1.2,
//! `DHKEM(X25519, HKDF-SHA256)` (`kem_id` 0x0020), the KDF `HKDF-SHA256`
//! (`kdf_id` 0x0001), and the AEADs of §7.3: `AES-128-GCM`, `AES-256-GCM` and
//! `ChaCha20Poly1305` — in all four modes of §5.1: base, PSK, auth and
//! auth-PSK. The P-256 and P-521 KEMs of Appendix A.3 onwards are not here.
//!
//! # What it promises
//!
//! A ciphertext is an encapsulated key `enc` and an AEAD ciphertext. Opening
//! it requires the recipient's private key, and returns `None` if the
//! encapsulation, the associated data, the info string or the ciphertext was
//! altered — the AEAD tag covers the message and the associated data, and the
//! key schedule binds the mode, the PSK identifier and the info string, so a
//! context built from different ones derives a different key.
//!
//! Auth mode additionally requires the sender's private key and binds the
//! sender's public key into the shared secret, so opening proves the message
//! came from the holder of that key. PSK mode mixes a pre-shared key into the
//! schedule. Neither hides the sender's or recipient's identity, and none of
//! the modes hides the message length.
//!
//! # Tests
//!
//! Every value of RFC 9180's Appendix A.1 and A.2 — both AEADs, all four
//! modes, the key derivation of §7.1.3, the encapsulated shared secret, the
//! key schedule's context string, secret, key, base nonce and exporter
//! secret, the nonces of the first two records, those records' ciphertexts
//! and the three exported values — is in `tests/vectors/hpke_rfc9180.txt`.
//! The module's own tests read it for the values below the public API;
//! `tests/kat_rfc9180_hpke.rs` reads it through the API, and adds the
//! refusals: a changed encapsulation, info string, associated data or
//! ciphertext, a low-order encapsulation, and the wrong key on either side.

use crate::ct::zeroize_slice;
use crate::hash::hkdf::Hkdf;
use crate::public_key::x25519::{X25519PrivateKey, X25519PublicKey, X25519_LEN};
use crate::vt::X25519;
use crate::{Aead, Aes128Ct, Aes256Ct, ChaCha20Poly1305, Csprng, Gcm, Sha256};

/// The KEM, KDF and AEAD identifiers of RFC 9180 §7, as the suite string and
/// the key schedule spell them.
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;

/// `Nsecret` for this KEM and `Nh` for this KDF: both a SHA-256 digest
/// (§7.1, §7.2).
const SECRET_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;

/// The version prefix every labelled derivation carries (§4).
const VERSION: &[u8] = b"HPKE-v1";

/// The modes of §5.1 Table 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeMode {
    /// `mode_base`: the recipient's key alone.
    Base,
    /// `mode_psk`: a pre-shared key beside it.
    Psk,
    /// `mode_auth`: the sender's key beside it.
    Auth,
    /// `mode_auth_psk`: both.
    AuthPsk,
}

impl HpkeMode {
    const fn id(self) -> u8 {
        match self {
            HpkeMode::Base => 0x00,
            HpkeMode::Psk => 0x01,
            HpkeMode::Auth => 0x02,
            HpkeMode::AuthPsk => 0x03,
        }
    }

    const fn uses_psk(self) -> bool {
        matches!(self, HpkeMode::Psk | HpkeMode::AuthPsk)
    }
}

/// The AEADs of §7.3 that this suite family offers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeAead {
    /// `aead_id` 0x0001: AES-128-GCM, 16-byte key.
    Aes128Gcm,
    /// `aead_id` 0x0002: AES-256-GCM, 32-byte key.
    Aes256Gcm,
    /// `aead_id` 0x0003: ChaCha20-Poly1305, 32-byte key.
    ChaCha20Poly1305,
}

impl HpkeAead {
    const fn id(self) -> u16 {
        match self {
            HpkeAead::Aes128Gcm => 0x0001,
            HpkeAead::Aes256Gcm => 0x0002,
            HpkeAead::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// `Nk`, the key length.
    const fn key_bytes(self) -> usize {
        match self {
            HpkeAead::Aes128Gcm => 16,
            HpkeAead::Aes256Gcm | HpkeAead::ChaCha20Poly1305 => 32,
        }
    }

    /// `Nn`, the nonce length; every AEAD here takes 96 bits.
    const fn nonce_bytes(self) -> usize {
        12
    }

    /// `Nt`, the tag length; every AEAD here produces 128 bits.
    const fn tag_bytes(self) -> usize {
        16
    }

    fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        let tag: Vec<u8> = match self {
            HpkeAead::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let aead = Gcm::new(Aes128Ct::new_wiping(&mut k));
                aead.encrypt_in_place(nonce, aad, &mut out).to_vec()
            }
            HpkeAead::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let aead = Gcm::new(Aes256Ct::new_wiping(&mut k));
                aead.encrypt_in_place(nonce, aad, &mut out).to_vec()
            }
            HpkeAead::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let aead = ChaCha20Poly1305::new_wiping(&mut k);
                aead.encrypt_in_place(&n, aad, &mut out).to_vec()
            }
        };
        out.extend_from_slice(&tag);
        out
    }

    fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let tag_at = ciphertext.len().checked_sub(self.tag_bytes())?;
        let (body, tag) = ciphertext.split_at(tag_at);
        let mut out = body.to_vec();
        let opened = match self {
            HpkeAead::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let aead = Gcm::new(Aes128Ct::new_wiping(&mut k));
                let mut t = [0u8; 16];
                t.copy_from_slice(tag);
                aead.decrypt_in_place(nonce, aad, &mut out, &t)
            }
            HpkeAead::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let aead = Gcm::new(Aes256Ct::new_wiping(&mut k));
                let mut t = [0u8; 16];
                t.copy_from_slice(tag);
                aead.decrypt_in_place(nonce, aad, &mut out, &t)
            }
            HpkeAead::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let mut t = [0u8; 16];
                t.copy_from_slice(tag);
                let aead = ChaCha20Poly1305::new_wiping(&mut k);
                aead.decrypt_in_place(&n, aad, &mut out, &t)
            }
        };
        if opened {
            Some(out)
        } else {
            zeroize_slice(out.as_mut_slice());
            None
        }
    }
}

/// `concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))`
/// (§5.1).
fn suite_id(aead: HpkeAead) -> [u8; 10] {
    let mut id = [0u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    id[8..10].copy_from_slice(&aead.id().to_be_bytes());
    id
}

/// `concat("KEM", I2OSP(kem_id, 2))` (§4.1), which the KEM's own derivations
/// use in place of the full suite string.
fn kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..5].copy_from_slice(&KEM_ID.to_be_bytes());
    id
}

/// `LabeledExtract(salt, label, ikm)` (§4): extract over
/// `"HPKE-v1" ‖ suite_id ‖ label ‖ ikm`.
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut labeled = Vec::with_capacity(VERSION.len() + suite.len() + label.len() + ikm.len());
    labeled.extend_from_slice(VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let prk = Hkdf::<Sha256>::extract(Some(salt), &labeled).prk().to_vec();
    zeroize_slice(labeled.as_mut_slice());
    prk
}

/// `LabeledExpand(prk, label, info, L)` (§4): expand over
/// `I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info`.
///
/// Returns `None` when `L` exceeds what HKDF can produce, or when the length
/// does not fit the two octets the encoding gives it.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    let width = u16::try_from(len).ok()?;
    let mut labeled_info =
        Vec::with_capacity(2 + VERSION.len() + suite.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&width.to_be_bytes());
    labeled_info.extend_from_slice(VERSION);
    labeled_info.extend_from_slice(suite);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let mut out = vec![0u8; len];
    let ok = Hkdf::<Sha256>::from_prk(prk)?.expand(&labeled_info, &mut out);
    zeroize_slice(labeled_info.as_mut_slice());
    if ok {
        Some(out)
    } else {
        zeroize_slice(out.as_mut_slice());
        None
    }
}

/// `ExtractAndExpand(dh, kem_context)` (§4.1).
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Option<Vec<u8>> {
    let kem = kem_suite_id();
    let mut eae_prk = labeled_extract(&kem, &[], b"eae_prk", dh);
    let shared = labeled_expand(&kem, &eae_prk, b"shared_secret", kem_context, SECRET_BYTES);
    zeroize_slice(eae_prk.as_mut_slice());
    shared
}

/// `DeriveKeyPair(ikm)` for the X25519 KEM (§7.1.3).
fn derive_key_pair(ikm: &[u8]) -> Option<(X25519PrivateKey, X25519PublicKey)> {
    let kem = kem_suite_id();
    let mut dkp_prk = labeled_extract(&kem, &[], b"dkp_prk", ikm);
    let mut sk = labeled_expand(&kem, &dkp_prk, b"sk", &[], X25519_LEN)?;
    zeroize_slice(dkp_prk.as_mut_slice());
    let mut scalar = [0u8; X25519_LEN];
    scalar.copy_from_slice(&sk);
    zeroize_slice(sk.as_mut_slice());
    let private = X25519PrivateKey::from_raw_bytes(&scalar);
    zeroize_slice(scalar.as_mut_slice());
    let public = private.to_public_key();
    Some((private, public))
}

/// One party's view of an established context: the AEAD key, the base nonce
/// the sequence number is XORed into, the exporter secret, and how many
/// messages have gone by (§5.2).
///
/// Sealing and opening advance the sequence number, so the two sides must
/// process messages in the same order.
pub struct HpkeContext {
    aead: HpkeAead,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    sequence: u64,
    suite: [u8; 10],
}

impl Drop for HpkeContext {
    fn drop(&mut self) {
        zeroize_slice(self.key.as_mut_slice());
        zeroize_slice(self.base_nonce.as_mut_slice());
        zeroize_slice(self.exporter_secret.as_mut_slice());
    }
}

impl core::fmt::Debug for HpkeContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HpkeContext(<redacted>)")
    }
}

impl HpkeContext {
    /// `ComputeNonce(seq)` (§5.2): the base nonce XORed with the sequence
    /// number, big-endian in the nonce's own width.
    fn nonce(&self) -> Vec<u8> {
        let mut nonce = self.base_nonce.clone();
        let seq = self.sequence.to_be_bytes();
        let offset = nonce.len() - seq.len();
        for (byte, seq_byte) in nonce[offset..].iter_mut().zip(seq.iter()) {
            *byte ^= seq_byte;
        }
        nonce
    }

    /// `IncrementSeq()` (§5.2), which refuses to wrap: a context that has
    /// sealed `2^64 - 1` messages is spent. The RFC's limit is
    /// `2^(8·Nn) - 1`, one per distinct nonce; a 64-bit counter reaches its
    /// own limit first and so never repeats a nonce.
    fn advance(&mut self) -> Option<()> {
        self.sequence = self.sequence.checked_add(1)?;
        Some(())
    }

    /// Seal `plaintext` with `aad` as the next message of this context.
    ///
    /// Returns `None` when the sequence number would wrap.
    #[must_use]
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = self.nonce();
        let ct = self.aead.seal(&self.key, &nonce, aad, plaintext);
        zeroize_slice(nonce.as_mut_slice());
        self.advance()?;
        Some(ct)
    }

    /// Open the next message of this context.
    ///
    /// Returns `None` if authentication fails, in which case the sequence
    /// number does not advance and the plaintext is wiped: a caller that
    /// retries must supply the message this context is waiting for.
    #[must_use]
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = self.nonce();
        let opened = self.aead.open(&self.key, &nonce, aad, ciphertext);
        zeroize_slice(nonce.as_mut_slice());
        let plaintext = opened?;
        self.advance()?;
        Some(plaintext)
    }

    /// `Export(exporter_context, L)` (§5.3): a secret of `len` bytes bound to
    /// this context and to `exporter_context`, for a caller that needs keying
    /// material beside the AEAD's.
    #[must_use]
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Option<Vec<u8>> {
        labeled_expand(
            &self.suite,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }

    /// How many messages this context has sealed or opened.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// `KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id)` (§5.1).
fn key_schedule(
    aead: HpkeAead,
    mode: HpkeMode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Option<HpkeContext> {
    // VerifyPSKInputs (§5.1): the key and its identifier appear together, and
    // only in the modes that take one.
    if psk.is_empty() != psk_id.is_empty() {
        return None;
    }
    if mode.uses_psk() == psk.is_empty() {
        return None;
    }

    let suite = suite_id(aead);
    let mut psk_id_hash = labeled_extract(&suite, &[], b"psk_id_hash", psk_id);
    let mut info_hash = labeled_extract(&suite, &[], b"info_hash", info);
    let mut context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    context.push(mode.id());
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);
    zeroize_slice(psk_id_hash.as_mut_slice());
    zeroize_slice(info_hash.as_mut_slice());

    let mut secret = labeled_extract(&suite, shared_secret, b"secret", psk);
    let key = labeled_expand(&suite, &secret, b"key", &context, aead.key_bytes());
    let base_nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, aead.nonce_bytes());
    let exporter_secret = labeled_expand(&suite, &secret, b"exp", &context, DIGEST_BYTES);
    zeroize_slice(secret.as_mut_slice());

    Some(HpkeContext {
        aead,
        key: key?,
        base_nonce: base_nonce?,
        exporter_secret: exporter_secret?,
        sequence: 0,
        suite,
    })
}

/// `Encap(pkR)` (§4.1): a fresh ephemeral key pair, the Diffie-Hellman shared
/// secret with the recipient, and the encapsulation that carries the ephemeral
/// public key.
fn encap<R: Csprng>(
    recipient: &X25519PublicKey,
    rng: &mut R,
) -> Option<(Vec<u8>, [u8; X25519_LEN])> {
    let (public, private) = X25519::generate(rng);
    encap_with_ephemeral(recipient, &private, &public)
}

fn encap_with_ephemeral(
    recipient: &X25519PublicKey,
    ephemeral: &X25519PrivateKey,
    ephemeral_public: &X25519PublicKey,
) -> Option<(Vec<u8>, [u8; X25519_LEN])> {
    let mut dh = ephemeral.agree(recipient)?;
    let enc = ephemeral_public.to_raw_bytes();
    let mut kem_context = Vec::with_capacity(2 * X25519_LEN);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&recipient.to_raw_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    zeroize_slice(dh.as_mut_slice());
    Some((shared?, enc))
}

/// `Decap(enc, skR)` (§4.1).
fn decap(enc: &[u8], recipient: &X25519PrivateKey) -> Option<Vec<u8>> {
    let peer = X25519PublicKey::from_raw_bytes(enc.try_into().ok()?);
    let mut dh = recipient.agree(&peer)?;
    let mut kem_context = Vec::with_capacity(2 * X25519_LEN);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&recipient.to_public_key().to_raw_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    zeroize_slice(dh.as_mut_slice());
    shared
}

/// `AuthEncap(pkR, skS)` (§4.1): the ephemeral agreement followed by the
/// sender's own, with both public keys bound into the context.
fn auth_encap_with_ephemeral(
    recipient: &X25519PublicKey,
    sender: &X25519PrivateKey,
    ephemeral: &X25519PrivateKey,
    ephemeral_public: &X25519PublicKey,
) -> Option<(Vec<u8>, [u8; X25519_LEN])> {
    let mut dh = Vec::with_capacity(2 * X25519_LEN);
    let mut ephemeral_dh = ephemeral.agree(recipient)?;
    let mut sender_dh = sender.agree(recipient)?;
    dh.extend_from_slice(&ephemeral_dh);
    dh.extend_from_slice(&sender_dh);
    zeroize_slice(ephemeral_dh.as_mut_slice());
    zeroize_slice(sender_dh.as_mut_slice());

    let enc = ephemeral_public.to_raw_bytes();
    let mut kem_context = Vec::with_capacity(3 * X25519_LEN);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&recipient.to_raw_bytes());
    kem_context.extend_from_slice(&sender.to_public_key().to_raw_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    zeroize_slice(dh.as_mut_slice());
    Some((shared?, enc))
}

/// `AuthDecap(enc, skR, pkS)` (§4.1).
fn auth_decap(
    enc: &[u8],
    recipient: &X25519PrivateKey,
    sender: &X25519PublicKey,
) -> Option<Vec<u8>> {
    let peer = X25519PublicKey::from_raw_bytes(enc.try_into().ok()?);
    let mut dh = Vec::with_capacity(2 * X25519_LEN);
    let mut ephemeral_dh = recipient.agree(&peer)?;
    let mut sender_dh = recipient.agree(sender)?;
    dh.extend_from_slice(&ephemeral_dh);
    dh.extend_from_slice(&sender_dh);
    zeroize_slice(ephemeral_dh.as_mut_slice());
    zeroize_slice(sender_dh.as_mut_slice());

    let mut kem_context = Vec::with_capacity(3 * X25519_LEN);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&recipient.to_public_key().to_raw_bytes());
    kem_context.extend_from_slice(&sender.to_raw_bytes());
    let shared = extract_and_expand(&dh, &kem_context);
    zeroize_slice(dh.as_mut_slice());
    shared
}

/// HPKE over DHKEM(X25519, HKDF-SHA256), RFC 9180.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hpke;

impl Hpke {
    /// `DeriveKeyPair(ikm)` (§7.1.3): the X25519 key pair an input keying
    /// material determines, for callers that derive a recipient's key from a
    /// seed rather than generating one.
    ///
    /// Returns `None` only if the expansion fails, which it cannot for a
    /// 32-byte output.
    #[must_use]
    pub fn derive_key_pair(ikm: &[u8]) -> Option<(X25519PrivateKey, X25519PublicKey)> {
        derive_key_pair(ikm)
    }

    /// `SetupBaseS(pkR, info)` (§5.1.1): an encapsulation and a sender
    /// context.
    #[must_use]
    pub fn setup_sender<R: Csprng>(
        aead: HpkeAead,
        recipient: &X25519PublicKey,
        info: &[u8],
        rng: &mut R,
    ) -> Option<([u8; X25519_LEN], HpkeContext)> {
        let (mut shared, enc) = encap(recipient, rng)?;
        let context = key_schedule(aead, HpkeMode::Base, &shared, info, &[], &[]);
        zeroize_slice(shared.as_mut_slice());
        Some((enc, context?))
    }

    /// `SetupBaseR(enc, skR, info)` (§5.1.1).
    #[must_use]
    pub fn setup_receiver(
        aead: HpkeAead,
        enc: &[u8],
        recipient: &X25519PrivateKey,
        info: &[u8],
    ) -> Option<HpkeContext> {
        let mut shared = decap(enc, recipient)?;
        let context = key_schedule(aead, HpkeMode::Base, &shared, info, &[], &[]);
        zeroize_slice(shared.as_mut_slice());
        context
    }

    /// `SetupPSKS(pkR, info, psk, psk_id)` (§5.1.2).
    #[must_use]
    pub fn setup_sender_psk<R: Csprng>(
        aead: HpkeAead,
        recipient: &X25519PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        rng: &mut R,
    ) -> Option<([u8; X25519_LEN], HpkeContext)> {
        let (mut shared, enc) = encap(recipient, rng)?;
        let context = key_schedule(aead, HpkeMode::Psk, &shared, info, psk, psk_id);
        zeroize_slice(shared.as_mut_slice());
        Some((enc, context?))
    }

    /// `SetupPSKR(enc, skR, info, psk, psk_id)` (§5.1.2).
    #[must_use]
    pub fn setup_receiver_psk(
        aead: HpkeAead,
        enc: &[u8],
        recipient: &X25519PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Option<HpkeContext> {
        let mut shared = decap(enc, recipient)?;
        let context = key_schedule(aead, HpkeMode::Psk, &shared, info, psk, psk_id);
        zeroize_slice(shared.as_mut_slice());
        context
    }

    /// `SetupAuthS(pkR, info, skS)` (§5.1.3).
    #[must_use]
    pub fn setup_sender_auth<R: Csprng>(
        aead: HpkeAead,
        recipient: &X25519PublicKey,
        info: &[u8],
        sender: &X25519PrivateKey,
        rng: &mut R,
    ) -> Option<([u8; X25519_LEN], HpkeContext)> {
        let (ephemeral_public, ephemeral) = X25519::generate(rng);
        let (mut shared, enc) =
            auth_encap_with_ephemeral(recipient, sender, &ephemeral, &ephemeral_public)?;
        let context = key_schedule(aead, HpkeMode::Auth, &shared, info, &[], &[]);
        zeroize_slice(shared.as_mut_slice());
        Some((enc, context?))
    }

    /// `SetupAuthR(enc, skR, info, pkS)` (§5.1.3).
    #[must_use]
    pub fn setup_receiver_auth(
        aead: HpkeAead,
        enc: &[u8],
        recipient: &X25519PrivateKey,
        info: &[u8],
        sender: &X25519PublicKey,
    ) -> Option<HpkeContext> {
        let mut shared = auth_decap(enc, recipient, sender)?;
        let context = key_schedule(aead, HpkeMode::Auth, &shared, info, &[], &[]);
        zeroize_slice(shared.as_mut_slice());
        context
    }

    /// `SetupAuthPSKS(pkR, info, psk, psk_id, skS)` (§5.1.4).
    #[must_use]
    pub fn setup_sender_auth_psk<R: Csprng>(
        aead: HpkeAead,
        recipient: &X25519PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender: &X25519PrivateKey,
        rng: &mut R,
    ) -> Option<([u8; X25519_LEN], HpkeContext)> {
        let (ephemeral_public, ephemeral) = X25519::generate(rng);
        let (mut shared, enc) =
            auth_encap_with_ephemeral(recipient, sender, &ephemeral, &ephemeral_public)?;
        let context = key_schedule(aead, HpkeMode::AuthPsk, &shared, info, psk, psk_id);
        zeroize_slice(shared.as_mut_slice());
        Some((enc, context?))
    }

    /// `SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)` (§5.1.4).
    #[must_use]
    pub fn setup_receiver_auth_psk(
        aead: HpkeAead,
        enc: &[u8],
        recipient: &X25519PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender: &X25519PublicKey,
    ) -> Option<HpkeContext> {
        let mut shared = auth_decap(enc, recipient, sender)?;
        let context = key_schedule(aead, HpkeMode::AuthPsk, &shared, info, psk, psk_id);
        zeroize_slice(shared.as_mut_slice());
        context
    }

    /// `Seal(pkR, info, aad, pt)` (§6.1): the single-shot base-mode API, which
    /// sets up a context, seals one message and discards the context.
    #[must_use]
    pub fn seal<R: Csprng>(
        aead: HpkeAead,
        recipient: &X25519PublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Option<([u8; X25519_LEN], Vec<u8>)> {
        let (enc, mut context) = Self::setup_sender(aead, recipient, info, rng)?;
        let ciphertext = context.seal(aad, plaintext)?;
        Some((enc, ciphertext))
    }

    /// `Open(enc, skR, info, aad, ct)` (§6.1).
    #[must_use]
    pub fn open(
        aead: HpkeAead,
        enc: &[u8],
        recipient: &X25519PrivateKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let mut context = Self::setup_receiver(aead, enc, recipient, info)?;
        context.open(aad, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{decode_hex, parse_vector_map};
    use std::collections::HashMap;

    const VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/hpke_rfc9180.txt"
    ));

    /// One subsection of Appendix A: the suite and mode as the vector file
    /// spells them, with the parameters they name.
    struct Case {
        tag: &'static str,
        aead: HpkeAead,
        mode: HpkeMode,
    }

    const CASES: [Case; 8] = [
        Case {
            tag: "AESGCM128_BASE",
            aead: HpkeAead::Aes128Gcm,
            mode: HpkeMode::Base,
        },
        Case {
            tag: "AESGCM128_PSK",
            aead: HpkeAead::Aes128Gcm,
            mode: HpkeMode::Psk,
        },
        Case {
            tag: "AESGCM128_AUTH",
            aead: HpkeAead::Aes128Gcm,
            mode: HpkeMode::Auth,
        },
        Case {
            tag: "AESGCM128_AUTHPSK",
            aead: HpkeAead::Aes128Gcm,
            mode: HpkeMode::AuthPsk,
        },
        Case {
            tag: "CHACHA20POLY1305_BASE",
            aead: HpkeAead::ChaCha20Poly1305,
            mode: HpkeMode::Base,
        },
        Case {
            tag: "CHACHA20POLY1305_PSK",
            aead: HpkeAead::ChaCha20Poly1305,
            mode: HpkeMode::Psk,
        },
        Case {
            tag: "CHACHA20POLY1305_AUTH",
            aead: HpkeAead::ChaCha20Poly1305,
            mode: HpkeMode::Auth,
        },
        Case {
            tag: "CHACHA20POLY1305_AUTHPSK",
            aead: HpkeAead::ChaCha20Poly1305,
            mode: HpkeMode::AuthPsk,
        },
    ];

    /// The value the appendix lists for `<tag>_<name>`, decoded from hex.
    fn field(map: &HashMap<&str, &str>, tag: &str, name: &str) -> Vec<u8> {
        let key = format!("{tag}_{name}");
        decode_hex(
            map.get(key.as_str())
                .unwrap_or_else(|| panic!("{key} in the vector file")),
        )
    }

    /// A field the mode may not have: the PSK and its identifier outside the
    /// PSK modes, the sender's key outside the auth modes. Absent means empty,
    /// which is what the key schedule and the KEM take for it.
    fn optional(map: &HashMap<&str, &str>, tag: &str, name: &str) -> Vec<u8> {
        map.get(format!("{tag}_{name}").as_str())
            .map(|hex| decode_hex(hex))
            .unwrap_or_default()
    }

    fn number(map: &HashMap<&str, &str>, tag: &str, name: &str) -> u64 {
        let key = format!("{tag}_{name}");
        map.get(key.as_str())
            .unwrap_or_else(|| panic!("{key} in the vector file"))
            .parse()
            .unwrap_or_else(|_| panic!("{key} is a number"))
    }

    fn private_key(bytes: &[u8]) -> X25519PrivateKey {
        X25519PrivateKey::from_raw_bytes(bytes.try_into().expect("a 32-byte scalar"))
    }

    fn public_key(bytes: &[u8]) -> X25519PublicKey {
        X25519PublicKey::from_raw_bytes(bytes.try_into().expect("a 32-byte u-coordinate"))
    }

    /// The suite identifiers of §7 are in the vector file, so the constants
    /// this module derives its suite string from are checked against it.
    #[test]
    fn suite_identifiers_match_the_appendix() {
        let map = parse_vector_map(VECTORS);
        for case in &CASES {
            let tag = case.tag;
            assert_eq!(
                u64::from(case.mode.id()),
                number(&map, tag, "MODE"),
                "{tag}: mode"
            );
            assert_eq!(
                u64::from(KEM_ID),
                number(&map, tag, "KEM_ID"),
                "{tag}: kem_id"
            );
            assert_eq!(
                u64::from(KDF_ID),
                number(&map, tag, "KDF_ID"),
                "{tag}: kdf_id"
            );
            assert_eq!(
                u64::from(case.aead.id()),
                number(&map, tag, "AEAD_ID"),
                "{tag}: aead_id"
            );
        }
    }

    /// `DeriveKeyPair(ikm)` of §7.1.3 for the ephemeral, recipient and — in the
    /// auth modes — sender key pairs the appendix lists.
    #[test]
    fn derive_key_pair_matches_the_appendix() {
        let map = parse_vector_map(VECTORS);
        for case in &CASES {
            let tag = case.tag;
            let mut roles = vec![("IKME", "SKEM", "PKEM"), ("IKMR", "SKRM", "PKRM")];
            if !optional(&map, tag, "IKMS").is_empty() {
                roles.push(("IKMS", "SKSM", "PKSM"));
            }
            for (ikm, sk, pk) in roles {
                let (private, public) =
                    derive_key_pair(&field(&map, tag, ikm)).expect("a derived key pair");
                assert_eq!(
                    private.to_raw_bytes().to_vec(),
                    field(&map, tag, sk),
                    "{tag}: {sk}"
                );
                assert_eq!(
                    public.to_raw_bytes().to_vec(),
                    field(&map, tag, pk),
                    "{tag}: {pk}"
                );
            }
        }
    }

    /// Encapsulation and decapsulation, each against the appendix's `enc` and
    /// shared secret: the sender's side with the appendix's own ephemeral key,
    /// the recipient's from `enc` alone.
    #[test]
    fn kem_matches_the_appendix() {
        let map = parse_vector_map(VECTORS);
        for case in &CASES {
            let tag = case.tag;
            let ephemeral = private_key(&field(&map, tag, "SKEM"));
            let ephemeral_public = public_key(&field(&map, tag, "PKEM"));
            let recipient = private_key(&field(&map, tag, "SKRM"));
            let recipient_public = public_key(&field(&map, tag, "PKRM"));
            let expected_enc = field(&map, tag, "ENC");
            let expected_shared = field(&map, tag, "SHARED_SECRET");
            let sender = optional(&map, tag, "SKSM");

            let (shared, enc) = if sender.is_empty() {
                encap_with_ephemeral(&recipient_public, &ephemeral, &ephemeral_public)
            } else {
                auth_encap_with_ephemeral(
                    &recipient_public,
                    &private_key(&sender),
                    &ephemeral,
                    &ephemeral_public,
                )
            }
            .expect("encapsulation");
            assert_eq!(enc.to_vec(), expected_enc, "{tag}: enc");
            assert_eq!(shared, expected_shared, "{tag}: encapsulated shared secret");

            let decapsulated = if sender.is_empty() {
                decap(&enc, &recipient)
            } else {
                auth_decap(&enc, &recipient, &public_key(&field(&map, tag, "PKSM")))
            }
            .expect("decapsulation");
            assert_eq!(
                decapsulated, expected_shared,
                "{tag}: decapsulated shared secret"
            );
        }
    }

    /// The key schedule of §5.1, value by value: the context string it builds,
    /// the secret it extracts, and the key, base nonce and exporter secret it
    /// expands. The first two are recomputed here, so a mislabelled extract
    /// shows up as itself rather than as a wrong key.
    #[test]
    fn key_schedule_matches_the_appendix() {
        let map = parse_vector_map(VECTORS);
        for case in &CASES {
            let tag = case.tag;
            let shared = field(&map, tag, "SHARED_SECRET");
            let info = field(&map, tag, "INFO");
            let psk = optional(&map, tag, "PSK");
            let psk_id = optional(&map, tag, "PSK_ID");

            let suite = suite_id(case.aead);
            let mut key_schedule_context = vec![case.mode.id()];
            key_schedule_context.extend_from_slice(&labeled_extract(
                &suite,
                &[],
                b"psk_id_hash",
                &psk_id,
            ));
            key_schedule_context.extend_from_slice(&labeled_extract(
                &suite,
                &[],
                b"info_hash",
                &info,
            ));
            assert_eq!(
                key_schedule_context,
                field(&map, tag, "KEY_SCHEDULE_CONTEXT"),
                "{tag}: key_schedule_context"
            );
            assert_eq!(
                labeled_extract(&suite, &shared, b"secret", &psk),
                field(&map, tag, "SECRET"),
                "{tag}: secret"
            );

            let context = key_schedule(case.aead, case.mode, &shared, &info, &psk, &psk_id)
                .expect("the key schedule");
            assert_eq!(context.key, field(&map, tag, "KEY"), "{tag}: key");
            assert_eq!(
                context.base_nonce,
                field(&map, tag, "BASE_NONCE"),
                "{tag}: base_nonce"
            );
            assert_eq!(
                context.exporter_secret,
                field(&map, tag, "EXPORTER_SECRET"),
                "{tag}: exporter_secret"
            );
        }
    }

    /// `ComputeNonce(seq)` of §5.2 for the two sequence numbers the appendix
    /// lists nonces for.
    #[test]
    fn computed_nonces_match_the_appendix() {
        let map = parse_vector_map(VECTORS);
        for case in &CASES {
            let tag = case.tag;
            let mut context = key_schedule(
                case.aead,
                case.mode,
                &field(&map, tag, "SHARED_SECRET"),
                &field(&map, tag, "INFO"),
                &optional(&map, tag, "PSK"),
                &optional(&map, tag, "PSK_ID"),
            )
            .expect("the key schedule");
            for sequence in 0..2u64 {
                assert_eq!(
                    context.nonce(),
                    field(&map, tag, &format!("SEQ{sequence}_NONCE")),
                    "{tag}: nonce at sequence {sequence}"
                );
                context
                    .advance()
                    .expect("a sequence number below the limit");
            }
        }
    }

    /// A context whose counter has reached its last value seals nothing more,
    /// so no nonce is ever used twice.
    #[test]
    fn a_spent_context_seals_nothing_further() {
        let mut context = key_schedule(
            HpkeAead::Aes128Gcm,
            HpkeMode::Base,
            &[0x01u8; SECRET_BYTES],
            b"info",
            &[],
            &[],
        )
        .expect("the key schedule");
        context.sequence = u64::MAX - 1;
        assert!(context.seal(b"aad", b"the last message").is_some());
        assert!(context.seal(b"aad", b"one too many").is_none());
        assert_eq!(context.sequence(), u64::MAX);
    }

    /// VerifyPSKInputs (§5.1): a key without its identifier, an identifier
    /// without its key, and a PSK given to a mode that takes none — or withheld
    /// from one that requires one — all refuse to build a context.
    #[test]
    fn key_schedule_refuses_inconsistent_psk_inputs() {
        let shared = [0x01u8; SECRET_BYTES];
        let psk = b"pre-shared key";
        let psk_id = b"identifier";
        let schedule = |mode, psk: &[u8], psk_id: &[u8]| {
            key_schedule(HpkeAead::Aes128Gcm, mode, &shared, b"info", psk, psk_id).is_some()
        };
        assert!(!schedule(HpkeMode::Psk, psk, &[]));
        assert!(!schedule(HpkeMode::Psk, &[], psk_id));
        assert!(!schedule(HpkeMode::Base, psk, psk_id));
        assert!(!schedule(HpkeMode::Auth, psk, psk_id));
        assert!(!schedule(HpkeMode::Psk, &[], &[]));
        assert!(!schedule(HpkeMode::AuthPsk, &[], &[]));
        assert!(schedule(HpkeMode::Base, &[], &[]));
        assert!(schedule(HpkeMode::Psk, psk, psk_id));
    }
}
